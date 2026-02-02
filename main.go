package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/peterh/liner"

	"e2e-message/internal/session"
)

var (
	line         *liner.State
	ctrlCPressed atomic.Bool
)

func main() {
	// Create a new session
	sess, err := session.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize session: %v\n", err)
		os.Exit(1)
	}

	// Setup liner for proper UTF-8 input handling
	line = liner.NewLiner()
	defer line.Close()

	// Let liner handle Ctrl+C
	line.SetCtrlCAborts(true)

	// Display welcome message and public key
	fmt.Println("=== E2E Message - End-to-End Encryption Tool ===")
	fmt.Println()
	fmt.Println("Your public key (share this with your peer):")
	fmt.Println(sess.GetPublicKeyBase64())
	fmt.Println()
	fmt.Println("Type 'help' for available commands.")
	fmt.Println()

	// Start interactive loop
	for {
		prompt := "> "
		if sess.IsEstablished() {
			_, recv := sess.GetMessageStats()
			if recv > 0 {
				prompt = fmt.Sprintf("[#%d] > ", sess.GetLastRecvMsgNum())
			}
		}
		input, err := line.Prompt(prompt)
		if err != nil {
			if err == liner.ErrPromptAborted {
				// Ctrl+C pressed
				if handleCtrlC() {
					return
				}
				continue
			}
			// Ignore other errors (EOF etc)
			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Add to history
		line.AppendHistory(input)

		// Check if input starts with number + space (auto-decrypt)
		if startsWithNumberSpace(input) {
			handleDecrypt(sess, input)
			continue
		}

		// Parse command and arguments
		parts := strings.SplitN(input, " ", 2)
		cmd := strings.ToLower(parts[0])
		var arg string
		if len(parts) > 1 {
			arg = parts[1]
		}

		switch cmd {
		case "key":
			handleKey(sess, arg)
		case "e":
			handleEncrypt(sess, arg)
		case "d":
			handleDecrypt(sess, arg)
		case "status":
			handleStatus(sess)
		case "help":
			handleHelp()
		case "quit", "exit", "q":
			if confirmExit() {
				fmt.Println("Goodbye!")
				return
			}
		default:
			fmt.Printf("Unknown command: %s. Type 'help' for available commands.\n", cmd)
		}
	}
}

// startsWithNumberSpace checks if input starts with digits followed by a space
func startsWithNumberSpace(input string) bool {
	if len(input) < 3 {
		return false
	}

	spaceIdx := strings.Index(input, " ")
	if spaceIdx < 1 {
		return false
	}

	for _, c := range input[:spaceIdx] {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

func handleCtrlC() bool {
	if ctrlCPressed.Load() {
		// Second Ctrl+C within timeout - exit
		fmt.Println("Goodbye!")
		return true
	}

	// First Ctrl+C - set flag and start timeout
	ctrlCPressed.Store(true)
	fmt.Println("\nPress Ctrl+C again within 2 seconds to exit, or type a command to continue...")

	// Reset flag after 2 seconds
	go func() {
		time.Sleep(2 * time.Second)
		ctrlCPressed.Store(false)
	}()

	return false
}

func confirmExit() bool {
	response, err := line.Prompt("Are you sure you want to exit? (y/N): ")
	if err != nil {
		return false
	}
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func handleKey(sess *session.Session, base64Key string) {
	if base64Key == "" {
		fmt.Println("Usage: key <base64-public-key>")
		return
	}

	if err := sess.SetPeerPublicKey(base64Key); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println("Peer public key imported successfully!")
	fmt.Println("Secure channel established. You can now encrypt and decrypt messages.")
	fmt.Println()

	// Display verification words
	words := sess.GetVerificationWords()
	if words != nil {
		fmt.Println("=== Security Verification ===")
		fmt.Println("Verify these words match on both sides to ensure no MITM attack:")
		fmt.Printf("  %s\n", strings.Join(words, " - "))
		fmt.Println()
	}
}

func handleEncrypt(sess *session.Session, plaintext string) {
	if plaintext == "" {
		fmt.Println("Usage: e <plaintext message>")
		return
	}

	ciphertext, err := sess.Encrypt(plaintext)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println(ciphertext)
}

func handleDecrypt(sess *session.Session, ciphertext string) {
	if ciphertext == "" {
		fmt.Println("Usage: <msgNum> <base64-ciphertext>")
		return
	}

	plaintext, err := sess.Decrypt(ciphertext)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println(plaintext)
}

func handleStatus(sess *session.Session) {
	fmt.Println("=== Session Status ===")
	fmt.Printf("Session established: %v\n", sess.IsEstablished())
	fmt.Println()
	fmt.Println("Your public key:")
	fmt.Println(sess.GetPublicKeyBase64())

	if sess.IsEstablished() {
		fmt.Println()
		fmt.Println("Peer's public key:")
		fmt.Println(sess.GetPeerPublicKeyBase64())
		fmt.Println()
		words := sess.GetVerificationWords()
		if words != nil {
			fmt.Println("Verification words:")
			fmt.Printf("  %s\n", strings.Join(words, " - "))
		}
		fmt.Println()
		send, recv := sess.GetMessageStats()
		fmt.Printf("Messages sent: %d, received: %d\n", send, recv)
		if recv > 0 {
			fmt.Printf("Last received message: #%d\n", sess.GetLastRecvMsgNum())
		}
		fmt.Println("(Each message uses a unique key for forward secrecy)")
	}
}

func handleHelp() {
	fmt.Println("=== Available Commands ===")
	fmt.Println()
	fmt.Println("  key <base64-public-key>  Import peer's public key to establish secure channel")
	fmt.Println("  e <plaintext>            Encrypt a message")
	fmt.Println("  <msgNum> <ciphertext>    Decrypt (auto-detected, no 'd' needed)")
	fmt.Println("  status                   Show current session status")
	fmt.Println("  help                     Show this help message")
	fmt.Println("  quit / exit / q          Exit the program")
	fmt.Println()
	fmt.Println("=== Usage Flow ===")
	fmt.Println()
	fmt.Println("1. Share your public key with your peer (displayed at startup)")
	fmt.Println("2. Import your peer's public key using: key <their-public-key>")
	fmt.Println("3. Verify the 5 words match on both sides (MITM protection)")
	fmt.Println("4. Encrypt: e <your message>")
	fmt.Println("5. Decrypt: paste the received message directly (e.g., 0 abc123...)")
	fmt.Println()
	fmt.Println("=== Exit ===")
	fmt.Println()
	fmt.Println("  - Type 'quit', 'exit', or 'q' to exit (with confirmation)")
	fmt.Println("  - Press Ctrl+C twice to force exit")
}
