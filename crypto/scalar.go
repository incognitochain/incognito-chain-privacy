package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	C25519 "github.com/incognitochain/incognito-chain-privacy/crypto/curve25519"
	"math/big"
	"sort"
)

type Scalar struct {
	key C25519.Key
}

func (sc Scalar) String() string {
	return fmt.Sprintf("%x", sc.key[:])
}

func (sc Scalar) MarshalText() ([]byte) {
	return []byte(fmt.Sprintf("%x", sc.key[:]))
}

func (sc *Scalar) UnmarshalText(data []byte) (*Scalar, error) {
	if sc == nil {
		sc = new(Scalar)
	}

	byteSlice, _ := hex.DecodeString(string(data))
	if len(byteSlice) != Ed25519KeySize {
		return nil, errors.New("Incorrect key size")
	}
	copy(sc.key[:], byteSlice)
	return sc, nil
}

func (sc Scalar) ToBytes() []byte {
	slice := sc.key.ToBytes()
	return slice[:]
}

func (sc *Scalar) FromBytes(b []byte) (*Scalar, error) {
	if sc == nil {
		sc = new(Scalar)
	}
	var array [Ed25519KeySize]byte
	copy(array[:], b)
	sc.key.FromBytes(array)

	if !C25519.ScValid(&sc.key) {
		return nil, errors.New("Scalar FromBytes bytes array is invalid")
	}
	return sc, nil
}

func (sc *Scalar) Set(a *Scalar) (*Scalar) {
	if sc == nil {
		sc = new(Scalar)
	}
	sc.key = a.key  // don't change a.key when changing sc.key
	return sc
}

func RandomScalar() *Scalar {
	sc := new(Scalar)
	key := C25519.RandomScalar()
	sc.key = *key
	return sc
}

func HashToScalar(data []byte) *Scalar {
	key := C25519.HashToScalar(data)
	sc := new(Scalar)
	sc.key = *key
	if !sc.ScalarValid() {
		return nil
	}
	return sc
}

func (sc *Scalar) FromUint64(i uint64) *Scalar {
	if sc == nil {
		sc = new(Scalar)
	}
	sc.key = *d2h(i)
	return sc
}

func (sc *Scalar) ToUint64() uint64 {
	if sc == nil {
		return 0
	}
	keyBN := new(big.Int).SetBytes(sc.ToBytes())
	return keyBN.Uint64()
}

func (sc *Scalar) Add(a, b *Scalar) *Scalar {
	if sc == nil {
		sc = new(Scalar)
	}
	var res C25519.Key
	C25519.ScAdd(&res, &a.key, &b.key)
	sc.key = res
	return sc
}

func (sc *Scalar) Sub(a, b *Scalar) *Scalar {
	if sc == nil {
		sc = new(Scalar)
	}
	var res C25519.Key
	C25519.ScSub(&res, &a.key, &b.key)
	sc.key = res
	return sc
}

func (sc *Scalar) Mul(a, b *Scalar) *Scalar {
	if sc == nil {
		sc = new(Scalar)
	}
	var res C25519.Key
	C25519.ScMul(&res, &a.key, &b.key)
	sc.key = res
	return sc
}

// a*b + c % l
func (sc *Scalar) MulAdd(a, b, c *Scalar) *Scalar {
	if sc == nil {
		sc = new(Scalar)
	}
	var res C25519.Key
	C25519.ScMulAdd(&res, &a.key, &b.key, &c.key)
	sc.key = res
	return sc
}

func (sc *Scalar) Exp(a *Scalar, v uint64) *Scalar {
	if sc == nil {
		sc = new(Scalar)
	}

	var res C25519.Key
	C25519.ScMul(&res, &a.key, &a.key)
	for i := 0; i < int(v)-2; i++ {
		C25519.ScMul(&res, &res, &a.key)
	}

	sc.key = res
	return sc
}

func (sc *Scalar) ScalarValid() bool {
	if sc == nil {
		return false
	}
	return C25519.ScValid(&sc.key)
}

// todo: improve performance
func CompareScalar(sca, scb *Scalar) int {
	tmpa := sca.ToBytes()
	tmpb := scb.ToBytes()

	for i := Ed25519KeySize - 1; i >= 0; i-- {
		if uint64(tmpa[i]) > uint64(tmpb[i]) {
			return 1
		}

		if uint64(tmpa[i]) < uint64(tmpb[i]) {
			return -1
		}
	}
	return 0
}

func CheckDuplicateScalarArray(arr []*Scalar) bool {
	sort.Slice(arr, func(i, j int) bool {
		return CompareScalar(arr[i], arr[j]) == -1
	})

	for i := 0; i < len(arr)-1; i++ {
		if CompareScalar(arr[i], arr[i+1]) == 0 {
			return true
		}
	}
	return false
}

func (sc *Scalar) Invert(a *Scalar) *Scalar {
	if sc == nil {
		sc = new(Scalar)
	}

	var inverse_result C25519.Key
	x := a.key

	reversex := Reverse(x)
	bigX := new(big.Int).SetBytes(reversex[:])

	reverseL := Reverse(C25519.CurveOrder()) // as speed improvements it can be made constant
	bigL := new(big.Int).SetBytes(reverseL[:])

	var inverse big.Int
	inverse.ModInverse(bigX, bigL)

	inverse_bytes := inverse.Bytes()

	if len(inverse_bytes) > Ed25519KeySize {
		panic("Inverse cannot be more than Ed25519KeySize bytes in this domain")
	}

	for i, j := 0, len(inverse_bytes)-1; i < j; i, j = i+1, j-1 {
		inverse_bytes[i], inverse_bytes[j] = inverse_bytes[j], inverse_bytes[i]
	}
	copy(inverse_result[:], inverse_bytes[:]) // copy the bytes  as they should be

	sc.key = inverse_result
	return sc
}

func Reverse(x C25519.Key) (result C25519.Key) {
	result = x
	// A key is in little-endian, but the big package wants the bytes in
	// big-endian, so Reverse them.
	blen := len(x) // its hardcoded 32 bytes, so why do len but lets do it
	for i := 0; i < blen/2; i++ {
		result[i], result[blen-1-i] = result[blen-1-i], result[i]
	}
	return
}

func d2h(val uint64) *C25519.Key {
	key := new(C25519.Key)
	for i := 0; val > 0; i++ {
		key[i] = byte(val & 0xFF)
		val /= 256
	}
	return key
}
