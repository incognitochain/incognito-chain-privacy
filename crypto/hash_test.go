package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSH3_256(t *testing.T) {
	data := [][]byte{
		{},                  // empty
		{1},                 // 1 bytes
		{1, 2, 3},           // 3 bytes
		{100, 200, 2, 1, 2}, // 5 bytes
		{16, 223, 34, 4, 35, 63, 73, 48, 69, 10, 11, 182, 183, 144, 150, 160, 17, 183, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33}, // 33 bytes
	}

	for _, item := range data {
		hash := SHA3_256(item)
		assert.Equal(t, HashSize, len(hash))
	}
}

func TestKeccak256(t *testing.T) {
	data := [][]byte{
		{},                  // empty
		{1},                 // 1 bytes
		{1, 2, 3},           // 3 bytes
		{100, 200, 2, 1, 2}, // 5 bytes
		{16, 223, 34, 4, 35, 63, 73, 48, 69, 10, 11, 182, 183, 144, 150, 160, 17, 183, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33}, // 33 bytes
	}

	for _, item := range data {
		hash := Keccak256(item)
		assert.Equal(t, HashSize, len(hash))
	}
}


