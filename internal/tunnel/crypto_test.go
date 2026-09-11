package tunnel

import (
	"bytes"
	"testing"

	"github.com/flynn/noise"
)

func mustKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	kp, err := newKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return kp.Private, kp.Public
}

// newSessionPair runs a full IK handshake in memory and returns the cipher
// states: initiator (send, recv) and responder (send, recv).
func newSessionPair(t *testing.T) (iSend, iRecv, rSend, rRecv *noise.CipherState) {
	t.Helper()
	iPriv, iPub := mustKeypair(t)
	rPriv, rPub := mustKeypair(t)

	init, err := newInitiator(iPriv, iPub, rPub)
	if err != nil {
		t.Fatalf("newInitiator: %v", err)
	}
	resp, err := newResponder(rPriv, rPub)
	if err != nil {
		t.Fatalf("newResponder: %v", err)
	}

	msg1, _, _, err := init.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("initiator write msg1: %v", err)
	}
	if _, _, _, err := resp.ReadMessage(nil, msg1); err != nil {
		t.Fatalf("responder read msg1: %v", err)
	}
	if got := resp.PeerStatic(); !bytes.Equal(got, iPub) {
		t.Fatalf("responder peer static mismatch:\n got %x\nwant %x", got, iPub)
	}
	msg2, r1, r2, err := resp.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("responder write msg2: %v", err)
	}
	_, i1, i2, err := init.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("initiator read msg2: %v", err)
	}
	// Noise spec ordering: the first CipherState is for initiator -> responder.
	return i1, i2, r2, r1
}

func TestPublicFromPrivate(t *testing.T) {
	priv, pub := mustKeypair(t)
	got, err := publicFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatalf("derived public key mismatch:\n got %x\nwant %x", got, pub)
	}
}

func TestHandshakeAndNonceSemantics(t *testing.T) {
	iSend, iRecv, rSend, rRecv := newSessionPair(t)
	ad := []byte{frameVersion, frameData}

	ct, err := iSend.Encrypt(nil, ad, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := rRecv.Decrypt(nil, ad, ct)
	if err != nil {
		t.Fatalf("responder decrypt: %v", err)
	}
	if string(pt) != "hello" {
		t.Fatalf("got %q", pt)
	}

	ct, err = rSend.Encrypt(nil, ad, []byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err = iRecv.Decrypt(nil, ad, ct)
	if err != nil {
		t.Fatalf("initiator decrypt: %v", err)
	}
	if string(pt) != "world" {
		t.Fatalf("got %q", pt)
	}

	// A tampered ciphertext is rejected and must not desync the session
	// (the nonce does not advance on failed decryption).
	ct2, err := iSend.Encrypt(nil, ad, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), ct2...)
	bad[len(bad)-1] ^= 0x01
	if _, err := rRecv.Decrypt(nil, ad, bad); err == nil {
		t.Fatal("tampered packet accepted")
	}
	pt, err = rRecv.Decrypt(nil, ad, ct2)
	if err != nil {
		t.Fatalf("session desynced after tampered packet: %v", err)
	}
	if string(pt) != "second" {
		t.Fatalf("got %q", pt)
	}
}

func TestHandshakeFailsWithWrongResponderKey(t *testing.T) {
	iPriv, iPub := mustKeypair(t)
	rPriv, rPub := mustKeypair(t)
	_, wrongPub := mustKeypair(t)

	init, err := newInitiator(iPriv, iPub, wrongPub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newResponder(rPriv, rPub)
	if err != nil {
		t.Fatal(err)
	}
	msg1, _, _, err := init.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := resp.ReadMessage(nil, msg1); err == nil {
		t.Fatal("handshake with wrong responder key must fail")
	}
}

// TestExplicitNoncesTolerateLossAndReorder verifies the property that makes
// the wire format robust: with explicit nonces the receiver can decrypt any
// packet independently, so lost or reordered datagrams cost only themselves.
func TestExplicitNoncesTolerateLossAndReorder(t *testing.T) {
	iSend, _, _, rRecv := newSessionPair(t)
	ad := []byte{frameVersion, frameData}

	enc := func(n uint64, s string) []byte {
		iSend.SetNonce(n)
		ct, err := iSend.Encrypt(nil, ad, []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return ct
	}
	dec := func(n uint64, ct []byte) (string, error) {
		rRecv.SetNonce(n)
		pt, err := rRecv.Decrypt(nil, ad, ct)
		return string(pt), err
	}

	ct1 := enc(1, "one") // nonce 0 was "lost in transit"
	ct2 := enc(2, "two")
	ct4 := enc(4, "four")
	ct3 := enc(3, "three")

	if s, err := dec(1, ct1); err != nil || s != "one" {
		t.Fatalf("after loss: %v %q", err, s)
	}
	if s, err := dec(4, ct4); err != nil || s != "four" {
		t.Fatalf("out of order: %v %q", err, s)
	}
	if s, err := dec(3, ct3); err != nil || s != "three" {
		t.Fatalf("out-of-order backfill: %v %q", err, s)
	}
	if s, err := dec(2, ct2); err != nil || s != "two" {
		t.Fatalf("backfill of the second packet: %v %q", err, s)
	}
}
