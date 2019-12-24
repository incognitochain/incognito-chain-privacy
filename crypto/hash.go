package crypto

import (
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/crypto"
)

// SHA3_256 calculates SHA3-256 hashing of input b
// and returns the result in bytes array.
func SHA3_256(b []byte) []byte {
	hash := sha3.Sum256(b)
	return hash[:]
}

// Keccak256 returns Keccak256 hash as a Hash object for storing and comparing
func Keccak256(data ...[]byte) []byte {
	h := crypto.Keccak256(data...)
	return h
}