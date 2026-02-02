package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// Ratchet implements a symmetric key ratchet for forward secrecy
// Each message uses a unique key derived from the chain, and old keys are deleted
type Ratchet struct {
	sendChainKey []byte // Chain key for sending
	recvChainKey []byte // Chain key for receiving
	sendMsgNum   uint32 // Send message counter
	recvMsgNum   uint32 // Receive message counter
	skippedKeys  map[uint32][]byte // Cache for out-of-order messages
	maxSkip      uint32 // Maximum messages to skip
	mu           sync.Mutex
}

// NewRatchet creates a new ratchet from a shared secret
// The initiator and responder get mirrored send/recv chains
func NewRatchet(sharedSecret []byte, isInitiator bool) (*Ratchet, error) {
	// Derive two chain keys from the shared secret
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("e2e-ratchet-chains"))

	chainKey1 := make([]byte, 32)
	chainKey2 := make([]byte, 32)

	if _, err := io.ReadFull(hkdfReader, chainKey1); err != nil {
		return nil, fmt.Errorf("failed to derive chain key 1: %w", err)
	}
	if _, err := io.ReadFull(hkdfReader, chainKey2); err != nil {
		return nil, fmt.Errorf("failed to derive chain key 2: %w", err)
	}

	r := &Ratchet{
		skippedKeys: make(map[uint32][]byte),
		maxSkip:     100, // Allow up to 100 skipped messages
	}

	// Initiator and responder use opposite chains
	if isInitiator {
		r.sendChainKey = chainKey1
		r.recvChainKey = chainKey2
	} else {
		r.sendChainKey = chainKey2
		r.recvChainKey = chainKey1
	}

	return r, nil
}

// NextSendKey returns the next message key for sending and ratchets forward
func (r *Ratchet) NextSendKey() ([]byte, uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	msgKey, newChainKey, err := r.deriveKeys(r.sendChainKey, r.sendMsgNum)
	if err != nil {
		return nil, 0, err
	}

	msgNum := r.sendMsgNum
	r.sendChainKey = newChainKey
	r.sendMsgNum++

	// Clear old chain key from memory (best effort)
	return msgKey, msgNum, nil
}

// GetRecvKey returns the message key for a specific message number
// Handles out-of-order message delivery
func (r *Ratchet) GetRecvKey(msgNum uint32) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we already have this key cached (out-of-order message)
	if key, ok := r.skippedKeys[msgNum]; ok {
		delete(r.skippedKeys, msgNum)
		return key, nil
	}

	// Message from the past that we already processed
	if msgNum < r.recvMsgNum {
		return nil, fmt.Errorf("message %d already received or too old", msgNum)
	}

	// Check if we need to skip too many messages
	if msgNum-r.recvMsgNum > r.maxSkip {
		return nil, fmt.Errorf("too many skipped messages: %d", msgNum-r.recvMsgNum)
	}

	// Skip ahead and cache intermediate keys
	for r.recvMsgNum < msgNum {
		skipKey, newChainKey, err := r.deriveKeys(r.recvChainKey, r.recvMsgNum)
		if err != nil {
			return nil, err
		}
		r.skippedKeys[r.recvMsgNum] = skipKey
		r.recvChainKey = newChainKey
		r.recvMsgNum++
	}

	// Now derive the key for the requested message
	msgKey, newChainKey, err := r.deriveKeys(r.recvChainKey, r.recvMsgNum)
	if err != nil {
		return nil, err
	}

	r.recvChainKey = newChainKey
	r.recvMsgNum++

	return msgKey, nil
}

// deriveKeys derives a message key and the next chain key from the current chain key
func (r *Ratchet) deriveKeys(chainKey []byte, msgNum uint32) ([]byte, []byte, error) {
	// Create input with message number for uniqueness
	input := make([]byte, 36)
	copy(input[:32], chainKey)
	binary.BigEndian.PutUint32(input[32:], msgNum)

	hkdfReader := hkdf.New(sha256.New, input, nil, []byte("e2e-msg-key"))

	msgKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, msgKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive message key: %w", err)
	}

	// Derive next chain key
	hkdfReader = hkdf.New(sha256.New, input, nil, []byte("e2e-chain-key"))
	newChainKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, newChainKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive chain key: %w", err)
	}

	return msgKey, newChainKey, nil
}

// GetSendMsgNum returns the current send message number
func (r *Ratchet) GetSendMsgNum() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sendMsgNum
}

// GetRecvMsgNum returns the current receive message number
func (r *Ratchet) GetRecvMsgNum() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recvMsgNum
}
