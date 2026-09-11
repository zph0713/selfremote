package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

var (
	errShortFrame = errors.New("tunnel: frame too short")
	errBadVersion = errors.New("tunnel: unsupported frame version")
)

// frameHeader returns the 2-byte header used by handshake frames.
func frameHeader(typ byte) []byte {
	return []byte{frameVersion, typ}
}

// parseFrame validates a received datagram and returns its type and payload.
// For data frames the payload begins with the 8-byte nonce.
func parseFrame(b []byte) (byte, []byte, error) {
	if len(b) < frameHeaderLen {
		return 0, nil, errShortFrame
	}
	if b[0] != frameVersion {
		return 0, nil, fmt.Errorf("%w: %#x", errBadVersion, b[0])
	}
	return b[1], b[frameHeaderLen:], nil
}

// sealDataFrame seals a payload into a data frame carrying an explicit nonce.
// The full frame header (version, type, nonce) is authenticated as associated
// data.
//
// Explicit nonces are what make the tunnel tolerant of packet loss and
// reordering: the receiver sets the nonce from the packet itself, so a lost
// datagram costs exactly that datagram — the session is unaffected. Replay
// protection lives in the receiver's sliding window, not in strict ordering.
func sealDataFrame(cs *noise.CipherState, typ byte, nonce uint64, payload []byte) ([]byte, error) {
	out := make([]byte, dataHeaderLen, dataHeaderLen+len(payload)+aeadTagLen)
	out[0], out[1] = frameVersion, typ
	binary.BigEndian.PutUint64(out[2:dataHeaderLen], nonce)
	cs.SetNonce(nonce)
	return cs.Encrypt(out, out[:dataHeaderLen], payload)
}

// dataNonce extracts the explicit nonce from a data frame payload
// (the datagram minus its 2-byte version/type prefix).
func dataNonce(payload []byte) (uint64, error) {
	if len(payload) < dataNonceLen {
		return 0, errShortFrame
	}
	return binary.BigEndian.Uint64(payload[:dataNonceLen]), nil
}
