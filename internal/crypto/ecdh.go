package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// GenerateKeyPair generates a new ECDH key pair using P-256 curve
func GenerateKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// ComputeSharedSecret computes the ECDH shared secret
func ComputeSharedSecret(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) ([]byte, error) {
	return privateKey.ECDH(peerPublicKey)
}

// DeriveAESKey derives a 32-byte AES key from the shared secret using HKDF-SHA256
func DeriveAESKey(sharedSecret []byte) ([]byte, error) {
	// Use HKDF with SHA-256 to derive a 32-byte key
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("e2e-message-aes-key"))

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %w", err)
	}

	return aesKey, nil
}

// ParsePublicKey parses a public key from bytes
func ParsePublicKey(data []byte) (*ecdh.PublicKey, error) {
	return ecdh.P256().NewPublicKey(data)
}
