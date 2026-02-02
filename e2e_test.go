package main

import (
	"testing"

	"e2e-message/internal/crypto"
	"e2e-message/internal/session"
)

func TestECDHKeyExchange(t *testing.T) {
	// Generate two key pairs
	keyA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair A: %v", err)
	}

	keyB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair B: %v", err)
	}

	// Compute shared secrets from both sides
	sharedA, err := crypto.ComputeSharedSecret(keyA, keyB.PublicKey())
	if err != nil {
		t.Fatalf("Failed to compute shared secret A: %v", err)
	}

	sharedB, err := crypto.ComputeSharedSecret(keyB, keyA.PublicKey())
	if err != nil {
		t.Fatalf("Failed to compute shared secret B: %v", err)
	}

	// Verify shared secrets are equal
	if string(sharedA) != string(sharedB) {
		t.Error("Shared secrets do not match")
	}
}

func TestAESEncryptDecrypt(t *testing.T) {
	// Generate a test key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Hello, World! This is a test message.")

	// Encrypt
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestRatchetForwardSecrecy(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	// Create two ratchets (initiator and responder)
	alice, err := crypto.NewRatchet(sharedSecret, true)
	if err != nil {
		t.Fatalf("Failed to create Alice's ratchet: %v", err)
	}

	bob, err := crypto.NewRatchet(sharedSecret, false)
	if err != nil {
		t.Fatalf("Failed to create Bob's ratchet: %v", err)
	}

	// Alice sends 3 messages
	var aliceKeys [][]byte
	var msgNums []uint32
	for i := 0; i < 3; i++ {
		key, msgNum, err := alice.NextSendKey()
		if err != nil {
			t.Fatalf("Failed to get send key %d: %v", i, err)
		}
		aliceKeys = append(aliceKeys, key)
		msgNums = append(msgNums, msgNum)
	}

	// Verify all keys are different (forward secrecy)
	for i := 0; i < len(aliceKeys); i++ {
		for j := i + 1; j < len(aliceKeys); j++ {
			if string(aliceKeys[i]) == string(aliceKeys[j]) {
				t.Errorf("Keys %d and %d are the same, violates forward secrecy", i, j)
			}
		}
	}

	// Bob receives in order
	for i := 0; i < 3; i++ {
		key, err := bob.GetRecvKey(msgNums[i])
		if err != nil {
			t.Fatalf("Failed to get recv key %d: %v", i, err)
		}
		if string(key) != string(aliceKeys[i]) {
			t.Errorf("Key mismatch for message %d", i)
		}
	}
}

func TestRatchetOutOfOrder(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	alice, _ := crypto.NewRatchet(sharedSecret, true)
	bob, _ := crypto.NewRatchet(sharedSecret, false)

	// Alice sends 3 messages
	key0, _, _ := alice.NextSendKey()
	key1, _, _ := alice.NextSendKey()
	key2, _, _ := alice.NextSendKey()

	// Bob receives out of order: 2, 0, 1
	bobKey2, err := bob.GetRecvKey(2)
	if err != nil {
		t.Fatalf("Failed to receive message 2: %v", err)
	}
	if string(bobKey2) != string(key2) {
		t.Error("Key mismatch for message 2")
	}

	bobKey0, err := bob.GetRecvKey(0)
	if err != nil {
		t.Fatalf("Failed to receive message 0: %v", err)
	}
	if string(bobKey0) != string(key0) {
		t.Error("Key mismatch for message 0")
	}

	bobKey1, err := bob.GetRecvKey(1)
	if err != nil {
		t.Fatalf("Failed to receive message 1: %v", err)
	}
	if string(bobKey1) != string(key1) {
		t.Error("Key mismatch for message 1")
	}
}

func TestSessionE2E(t *testing.T) {
	// Create two sessions (simulating Alice and Bob)
	alice, err := session.NewSession()
	if err != nil {
		t.Fatalf("Failed to create Alice's session: %v", err)
	}

	bob, err := session.NewSession()
	if err != nil {
		t.Fatalf("Failed to create Bob's session: %v", err)
	}

	// Exchange public keys
	alicePubKey := alice.GetPublicKeyBase64()
	bobPubKey := bob.GetPublicKeyBase64()

	// Alice imports Bob's public key
	if err := alice.SetPeerPublicKey(bobPubKey); err != nil {
		t.Fatalf("Alice failed to import Bob's key: %v", err)
	}

	// Bob imports Alice's public key
	if err := bob.SetPeerPublicKey(alicePubKey); err != nil {
		t.Fatalf("Bob failed to import Alice's key: %v", err)
	}

	// Verify sessions are established
	if !alice.IsEstablished() {
		t.Error("Alice's session not established")
	}
	if !bob.IsEstablished() {
		t.Error("Bob's session not established")
	}

	// Alice sends a message to Bob
	message := "Hello Bob! This is a secret message."
	encrypted, err := alice.Encrypt(message)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}

	// Bob decrypts the message
	decrypted, err := bob.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	if decrypted != message {
		t.Errorf("Message mismatch: got %q, want %q", decrypted, message)
	}

	// Bob sends a reply to Alice
	reply := "Hi Alice! Got your message."
	encryptedReply, err := bob.Encrypt(reply)
	if err != nil {
		t.Fatalf("Bob failed to encrypt reply: %v", err)
	}

	// Alice decrypts the reply
	decryptedReply, err := alice.Decrypt(encryptedReply)
	if err != nil {
		t.Fatalf("Alice failed to decrypt reply: %v", err)
	}

	if decryptedReply != reply {
		t.Errorf("Reply mismatch: got %q, want %q", decryptedReply, reply)
	}

	// Verify message stats
	aliceSend, aliceRecv := alice.GetMessageStats()
	bobSend, bobRecv := bob.GetMessageStats()

	if aliceSend != 1 || aliceRecv != 1 {
		t.Errorf("Alice stats wrong: send=%d, recv=%d", aliceSend, aliceRecv)
	}
	if bobSend != 1 || bobRecv != 1 {
		t.Errorf("Bob stats wrong: send=%d, recv=%d", bobSend, bobRecv)
	}
}

func TestSessionForwardSecrecy(t *testing.T) {
	alice, _ := session.NewSession()
	bob, _ := session.NewSession()

	alice.SetPeerPublicKey(bob.GetPublicKeyBase64())
	bob.SetPeerPublicKey(alice.GetPublicKeyBase64())

	// Send multiple messages and verify each has different ciphertext
	message := "Same message"
	var ciphertexts []string

	for i := 0; i < 5; i++ {
		ct, err := alice.Encrypt(message)
		if err != nil {
			t.Fatalf("Encrypt %d failed: %v", i, err)
		}
		ciphertexts = append(ciphertexts, ct)
	}

	// All ciphertexts should be different (different keys used)
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			if ciphertexts[i] == ciphertexts[j] {
				t.Errorf("Ciphertexts %d and %d are same, forward secrecy violated", i, j)
			}
		}
	}

	// Bob should be able to decrypt all
	for i, ct := range ciphertexts {
		pt, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt %d failed: %v", i, err)
		}
		if pt != message {
			t.Errorf("Message %d mismatch", i)
		}
	}
}

func TestSessionNotEstablished(t *testing.T) {
	sess, err := session.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Try to encrypt without establishing session
	_, err = sess.Encrypt("test")
	if err == nil {
		t.Error("Expected error when encrypting without established session")
	}

	// Try to decrypt without establishing session
	_, err = sess.Decrypt("dGVzdA==")
	if err == nil {
		t.Error("Expected error when decrypting without established session")
	}
}

func TestInvalidPublicKey(t *testing.T) {
	sess, err := session.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Try to import invalid public key
	err = sess.SetPeerPublicKey("invalid-base64!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	// Try to import valid base64 but invalid key
	err = sess.SetPeerPublicKey("dGVzdA==") // "test" in base64
	if err == nil {
		t.Error("Expected error for invalid public key")
	}
}

func TestVerificationWords(t *testing.T) {
	// Create two sessions
	alice, err := session.NewSession()
	if err != nil {
		t.Fatalf("Failed to create Alice's session: %v", err)
	}

	bob, err := session.NewSession()
	if err != nil {
		t.Fatalf("Failed to create Bob's session: %v", err)
	}

	// Verification words should be nil before session established
	if alice.GetVerificationWords() != nil {
		t.Error("Expected nil verification words before session established")
	}

	// Exchange keys
	if err := alice.SetPeerPublicKey(bob.GetPublicKeyBase64()); err != nil {
		t.Fatalf("Alice failed to import Bob's key: %v", err)
	}
	if err := bob.SetPeerPublicKey(alice.GetPublicKeyBase64()); err != nil {
		t.Fatalf("Bob failed to import Alice's key: %v", err)
	}

	// Get verification words
	aliceWords := alice.GetVerificationWords()
	bobWords := bob.GetVerificationWords()

	if aliceWords == nil || bobWords == nil {
		t.Fatal("Expected non-nil verification words after session established")
	}

	if len(aliceWords) != 5 || len(bobWords) != 5 {
		t.Errorf("Expected 5 words, got Alice: %d, Bob: %d", len(aliceWords), len(bobWords))
	}

	// Both sides should have the same words
	for i := 0; i < 5; i++ {
		if aliceWords[i] != bobWords[i] {
			t.Errorf("Word mismatch at index %d: Alice=%s, Bob=%s", i, aliceWords[i], bobWords[i])
		}
	}

	t.Logf("Verification words: %v", aliceWords)
}
