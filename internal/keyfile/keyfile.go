// Package keyfile reads and writes passphrase-encrypted selfremote client
// configuration files ("key files").
//
// A key file is a JSON envelope:
//
//	{
//	  "srkey": 1,
//	  "kdf":    {"name":"argon2id","salt":"…","time":3,"memory":65536,"threads":4,"keylen":32},
//	  "cipher": {"name":"chacha20poly1305","nonce":"…"},
//	  "ct":     "…base64…"
//	}
//
// The plaintext inside is a client config JSON (see internal/config.Client).
// Key derivation: argon2id(passphrase, salt) -> 32-byte key; encryption:
// ChaCha20-Poly1305 with a random nonce. The KDF parameters are stored in the
// envelope so future parameter changes stay compatible.
package keyfile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	envelopeVersion = 1
	aad             = "selfremote-keyfile-v1"

	defaultTime    = 3
	defaultMemory  = 64 * 1024 // KiB = 64 MiB
	defaultThreads = 4
	keyLen         = 32

	// Sanity caps against hostile envelopes (they are usually self-made, but
	// a malicious file should not be able to make us allocate GBs).
	maxTime    = 16
	maxMemory  = 1024 * 1024 // 1 GiB
	maxThreads = 32
)

// ErrWrongPassphrase is returned when decryption fails — almost always a wrong
// passphrase (AEAD cannot distinguish that from corruption, by design).
var ErrWrongPassphrase = errors.New("密钥文件密码错误（或文件已损坏）")

type kdfParams struct {
	Name    string `json:"name"`
	Salt    string `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keylen"`
}

type cipherParams struct {
	Name  string `json:"name"`
	Nonce string `json:"nonce"`
}

type envelope struct {
	Version int          `json:"srkey"`
	KDF     kdfParams    `json:"kdf"`
	Cipher  cipherParams `json:"cipher"`
	CT      string       `json:"ct"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Seal encrypts plain with passphrase and returns the envelope JSON.
func Seal(plain []byte, passphrase string) ([]byte, error) {
	if len(passphrase) < 8 {
		return nil, errors.New("passphrase must be at least 8 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(passphrase), salt, defaultTime, defaultMemory, defaultThreads, keyLen)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, []byte(aad))

	env := envelope{
		Version: envelopeVersion,
		KDF: kdfParams{
			Name: "argon2id", Salt: b64(salt),
			Time: defaultTime, Memory: defaultMemory, Threads: defaultThreads, KeyLen: keyLen,
		},
		Cipher: cipherParams{Name: "chacha20poly1305", Nonce: b64(nonce)},
		CT:     b64(ct),
	}
	return json.MarshalIndent(env, "", "  ")
}

// Open decrypts an envelope with passphrase and returns the plaintext.
func Open(data []byte, passphrase string) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("不是有效的密钥文件: %w", err)
	}
	if env.Version != envelopeVersion {
		return nil, fmt.Errorf("不支持的密钥文件版本: %d（请升级 selfremote）", env.Version)
	}
	if env.KDF.Name != "argon2id" || env.Cipher.Name != "chacha20poly1305" {
		return nil, fmt.Errorf("不支持的加密参数: kdf=%s cipher=%s", env.KDF.Name, env.Cipher.Name)
	}
	if env.KDF.Time == 0 || env.KDF.Time > maxTime ||
		env.KDF.Memory == 0 || env.KDF.Memory > maxMemory ||
		env.KDF.Threads == 0 || env.KDF.Threads > maxThreads ||
		env.KDF.KeyLen != keyLen {
		return nil, errors.New("密钥文件参数异常，已拒绝")
	}
	salt, err := base64.StdEncoding.DecodeString(env.KDF.Salt)
	if err != nil || len(salt) < 8 {
		return nil, errors.New("密钥文件损坏（salt）")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Cipher.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSize {
		return nil, errors.New("密钥文件损坏（nonce）")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil || len(ct) < chacha20poly1305.Overhead {
		return nil, errors.New("密钥文件损坏（密文）")
	}

	key := argon2.IDKey([]byte(passphrase), salt, env.KDF.Time, env.KDF.Memory, env.KDF.Threads, env.KDF.KeyLen)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return plain, nil
}

// IsEnvelope reports whether data looks like a key-file envelope (rather than
// a plain config JSON).
func IsEnvelope(data []byte) bool {
	var probe struct {
		SRKey *int `json:"srkey"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.SRKey != nil
}
