package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseFrame(t *testing.T) {
	if _, _, err := parseFrame([]byte{frameVersion}); !errors.Is(err, errShortFrame) {
		t.Fatalf("short frame: got %v", err)
	}
	if _, _, err := parseFrame([]byte{0x02, frameData, 1}); !errors.Is(err, errBadVersion) {
		t.Fatalf("bad version: got %v", err)
	}
	typ, payload, err := parseFrame([]byte{frameVersion, frameData, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if typ != frameData || !bytes.Equal(payload, []byte{1, 2, 3}) {
		t.Fatalf("got type=%#x payload=%x", typ, payload)
	}
}

func TestSealDataFrameNonceAndAD(t *testing.T) {
	iSend, _, _, rRecv := newSessionPair(t)

	const nonce = 0x0102030405060708
	f, err := sealDataFrame(iSend, frameData, nonce, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if f[0] != frameVersion || f[1] != frameData {
		t.Fatalf("bad header: %x", f[:frameHeaderLen])
	}
	if got := binary.BigEndian.Uint64(f[2:dataHeaderLen]); got != nonce {
		t.Fatalf("nonce not encoded: %#x", got)
	}
	n, err := dataNonce(f[frameHeaderLen:])
	if err != nil || n != nonce {
		t.Fatalf("dataNonce: %v %#x", err, n)
	}
	if _, err := dataNonce([]byte{1, 2}); !errors.Is(err, errShortFrame) {
		t.Fatalf("short payload: got %v", err)
	}

	// The header is authenticated: changing the type must break decryption.
	wrongAd := append([]byte(nil), f[:dataHeaderLen]...)
	wrongAd[1] = frameKeepalive
	rRecv.SetNonce(nonce)
	if _, err := rRecv.Decrypt(nil, wrongAd, f[dataHeaderLen:]); err == nil {
		t.Fatal("frame decrypted under a different header")
	}
	rRecv.SetNonce(nonce)
	pt, err := rRecv.Decrypt(nil, f[:dataHeaderLen], f[dataHeaderLen:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "payload" {
		t.Fatalf("got %q", pt)
	}
}
