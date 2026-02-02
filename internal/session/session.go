package session

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"e2e-message/internal/crypto"
)

// Session represents an E2E encryption session with forward secrecy
type Session struct {
	privateKey  *ecdh.PrivateKey // Our private key
	publicKey   []byte           // Our public key bytes
	peerPubKey  []byte           // Peer's public key bytes
	ratchet     *crypto.Ratchet  // Key ratchet for forward secrecy
	aesKey      []byte           // Base AES key (for verification words)
	established bool             // Whether the session is established
	isInitiator bool             // Whether we initiated (our pubkey < peer's)
}

// NewSession creates a new session and generates a key pair
func NewSession() (*Session, error) {
	privateKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &Session{
		privateKey:  privateKey,
		publicKey:   privateKey.PublicKey().Bytes(),
		established: false,
	}, nil
}

// GetPublicKeyBase64 returns our public key encoded in Base64
func (s *Session) GetPublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

// SetPeerPublicKey imports the peer's public key and derives the shared secret
func (s *Session) SetPeerPublicKey(base64Key string) error {
	// Decode Base64 public key
	peerKeyBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return fmt.Errorf("invalid Base64 encoding: %w", err)
	}

	// Parse the public key
	peerPubKey, err := crypto.ParsePublicKey(peerKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Compute shared secret
	sharedSecret, err := crypto.ComputeSharedSecret(s.privateKey, peerPubKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive base AES key (for verification words)
	aesKey, err := crypto.DeriveAESKey(sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to derive AES key: %w", err)
	}

	// Determine who is initiator (lexicographically smaller pubkey)
	s.isInitiator = string(s.publicKey) < string(peerKeyBytes)

	// Create ratchet for forward secrecy
	ratchet, err := crypto.NewRatchet(sharedSecret, s.isInitiator)
	if err != nil {
		return fmt.Errorf("failed to create ratchet: %w", err)
	}

	s.peerPubKey = peerKeyBytes
	s.aesKey = aesKey
	s.ratchet = ratchet
	s.established = true

	return nil
}

// Encrypt encrypts a plaintext message and returns Base64 encoded ciphertext
// Each message uses a unique key (forward secrecy)
// Format: msgNum (4 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
func (s *Session) Encrypt(plaintext string) (string, error) {
	if !s.established {
		return "", fmt.Errorf("session not established: please import peer's public key first")
	}

	// Get next message key from ratchet
	msgKey, msgNum, err := s.ratchet.NextSendKey()
	if err != nil {
		return "", fmt.Errorf("failed to get message key: %w", err)
	}

	// Encrypt with the unique message key
	ciphertext, err := crypto.Encrypt([]byte(plaintext), msgKey)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	// Prepend message number for receiver to derive correct key
	result := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(result[:4], msgNum)
	copy(result[4:], ciphertext)

	// Clear message key from memory (best effort)
	for i := range msgKey {
		msgKey[i] = 0
	}

	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts a Base64 encoded ciphertext and returns the plaintext
// Uses the message number to derive the correct key
func (s *Session) Decrypt(base64Ciphertext string) (string, error) {
	if !s.established {
		return "", fmt.Errorf("session not established: please import peer's public key first")
	}

	data, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		return "", fmt.Errorf("invalid Base64 encoding: %w", err)
	}

	if len(data) < 4 {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Extract message number
	msgNum := binary.BigEndian.Uint32(data[:4])
	ciphertext := data[4:]

	// Get the message key for this message number
	msgKey, err := s.ratchet.GetRecvKey(msgNum)
	if err != nil {
		return "", fmt.Errorf("failed to get message key: %w", err)
	}

	// Decrypt with the message key
	plaintext, err := crypto.Decrypt(ciphertext, msgKey)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	// Clear message key from memory (best effort)
	for i := range msgKey {
		msgKey[i] = 0
	}

	return string(plaintext), nil
}

// IsEstablished returns whether the session has been established
func (s *Session) IsEstablished() bool {
	return s.established
}

// GetPeerPublicKeyBase64 returns the peer's public key encoded in Base64
func (s *Session) GetPeerPublicKeyBase64() string {
	if s.peerPubKey == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(s.peerPubKey)
}

// GetVerificationWords returns 5 words derived from the shared secret
// Both parties should see the same words if no MITM attack occurred
func (s *Session) GetVerificationWords() []string {
	if !s.established || s.aesKey == nil {
		return nil
	}
	return crypto.GenerateVerificationWords(s.aesKey)
}

// GetMessageStats returns the current send/receive message counts
func (s *Session) GetMessageStats() (send, recv uint32) {
	if s.ratchet == nil {
		return 0, 0
	}
	return s.ratchet.GetSendMsgNum(), s.ratchet.GetRecvMsgNum()
}
