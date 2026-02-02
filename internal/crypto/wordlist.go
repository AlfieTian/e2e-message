package crypto

import (
	"crypto/sha256"
	"encoding/binary"
)

// wordlist contains simple English words for key verification
// Using a subset of common words for easy pronunciation and memorization
var wordlist = []string{
	"apple", "banana", "cherry", "dragon", "eagle",
	"falcon", "garden", "harbor", "island", "jungle",
	"kitten", "lemon", "mango", "nectar", "orange",
	"panda", "quartz", "rabbit", "salmon", "tiger",
	"umbrella", "violet", "walnut", "xenon", "yellow",
	"zebra", "anchor", "bridge", "castle", "delta",
	"echo", "forest", "guitar", "hammer", "ivory",
	"jacket", "kernel", "laptop", "marble", "needle",
	"ocean", "pencil", "queen", "river", "sunset",
	"temple", "unity", "valley", "window", "xerox",
	"yacht", "zenith", "alpha", "beta", "gamma",
	"delta", "epsilon", "zeta", "theta", "kappa",
	"lambda", "sigma", "omega", "phoenix", "crypto",
	"cipher", "binary", "matrix", "vector", "prism",
	"quantum", "plasma", "nebula", "comet", "orbit",
	"lunar", "solar", "stellar", "cosmic", "galaxy",
	"planet", "meteor", "aurora", "vertex", "nexus",
	"apex", "summit", "zenith", "peak", "crown",
	"royal", "noble", "brave", "swift", "bold",
	"calm", "pure", "wise", "true", "free",
	"light", "spark", "flame", "blaze", "glow",
	"shine", "gleam", "flash", "beam", "ray",
	"wave", "tide", "stream", "brook", "creek",
	"lake", "pond", "pool", "spring", "well",
	"rain", "snow", "frost", "mist", "cloud",
	"storm", "wind", "breeze", "gust", "draft",
	"dawn", "dusk", "noon", "night", "star",
	"moon", "sun", "sky", "earth", "stone",
	"rock", "sand", "dust", "clay", "soil",
	"tree", "leaf", "root", "bark", "branch",
	"seed", "bloom", "petal", "thorn", "vine",
	"grass", "fern", "moss", "reed", "kelp",
	"coral", "shell", "pearl", "jade", "ruby",
	"gold", "silver", "bronze", "copper", "iron",
	"steel", "zinc", "lead", "tin", "brass",
	"crystal", "diamond", "emerald", "topaz", "opal",
	"amber", "onyx", "obsidian", "granite", "basalt",
	"maple", "willow", "cedar", "pine", "birch",
	"oak", "elm", "ash", "beech", "palm",
	"rose", "lily", "tulip", "daisy", "lotus",
	"orchid", "iris", "peony", "poppy", "clover",
	"mint", "basil", "sage", "thyme", "dill",
	"pepper", "ginger", "cumin", "curry", "chili",
	"honey", "sugar", "cream", "butter", "cheese",
	"bread", "cake", "cookie", "candy", "jelly",
	"coffee", "cocoa", "vanilla", "caramel", "maple",
	"north", "south", "east", "west", "center",
	"left", "right", "front", "back", "middle",
	"first", "second", "third", "fourth", "fifth",
	"one", "two", "three", "four", "five",
	"six", "seven", "eight", "nine", "ten",
	"red", "blue", "green", "white", "black",
}

// GenerateVerificationWords generates 5 verification words from a key
// Both parties should see the same words if no MITM attack occurred
func GenerateVerificationWords(key []byte) []string {
	// Hash the key to get consistent output
	hash := sha256.Sum256(key)

	words := make([]string, 5)
	for i := 0; i < 5; i++ {
		// Use 2 bytes for each word index
		index := binary.BigEndian.Uint16(hash[i*2:i*2+2]) % uint16(len(wordlist))
		words[i] = wordlist[index]
	}

	return words
}
