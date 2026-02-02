package session

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"e2e-message/internal/crypto"
)

// Session represents an E2E encryption session with forward secrecy
type Session struct {
	privateKey     *ecdh.PrivateKey // Our private key
	publicKey      []byte           // Our public key bytes
	peerPubKey     []byte           // Peer's public key bytes
	ratchet        *crypto.Ratchet  // Key ratchet for forward secrecy
	aesKey         []byte           // Base AES key (for verification words)
	established    bool             // Whether the session is established
	isInitiator    bool             // Whether we initiated (our pubkey < peer's)
	lastRecvMsgNum uint32           // Last successfully received message number
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

// Encrypt encrypts a plaintext message and returns formatted ciphertext
// Each message uses a unique key (forward secrecy)
// Format: "msgNum base64_ciphertext" (e.g., "0 abc123...")
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

	// Clear message key from memory (best effort)
	for i := range msgKey {
		msgKey[i] = 0
	}

	// Format: "msgNum base64_ciphertext"
	return fmt.Sprintf("%d %s", msgNum, base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// Decrypt decrypts a formatted ciphertext and returns the plaintext
// Format: "msgNum base64_ciphertext" (e.g., "0 abc123...")
func (s *Session) Decrypt(input string) (string, error) {
	if !s.established {
		return "", fmt.Errorf("session not established: please import peer's public key first")
	}

	// Parse "msgNum base64_ciphertext"
	parts := strings.SplitN(input, " ", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid format: expected 'msgNum base64_ciphertext'")
	}

	msgNum, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid message number: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid Base64 encoding: %w", err)
	}

	// Get the message key for this message number
	msgKey, err := s.ratchet.GetRecvKey(uint32(msgNum))
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

	// Store last received message number
	s.lastRecvMsgNum = uint32(msgNum)

	return string(plaintext), nil
}

// GetLastRecvMsgNum returns the last successfully received message number
func (s *Session) GetLastRecvMsgNum() uint32 {
	return s.lastRecvMsgNum
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
