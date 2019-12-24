package bulletproof

import (
	"errors"
	"github.com/incognitochain/incognito-chain-privacy/crypto"
	"math"
)

const (
	maxExp               = 64
	numOutputParam       = 32
	maxOutputNumber      = 32
	numCommitValue       = 5
	maxOutputNumberParam = 256
)

// bulletproofParams includes all generator for aggregated range proof
type bulletproofParams struct {
	g  []*crypto.Point
	h  []*crypto.Point
	u  *crypto.Point
	cs []byte
}

var AggParam = newBulletproofParams(numOutputParam)

func newBulletproofParams(m int) *bulletproofParams {
	gen := new(bulletproofParams)
	gen.cs = []byte{}
	capacity := maxExp * m // fixed value
	gen.g = make([]*crypto.Point, capacity)
	gen.h = make([]*crypto.Point, capacity)
	csByteH := []byte{}
	csByteG := []byte{}
	for i := 0; i < capacity; i++ {
		gen.g[i] = crypto.HashToPointFromIndex(int64(numCommitValue + i), crypto.CStringBulletProof)
		gen.h[i] = crypto.HashToPointFromIndex(int64(numCommitValue + i + maxOutputNumberParam*maxExp), crypto.CStringBulletProof)
		csByteG = append(csByteG, gen.g[i].ToBytesS()...)
		csByteH = append(csByteH, gen.h[i].ToBytesS()...)
	}

	gen.u = new(crypto.Point)
	gen.u = crypto.HashToPointFromIndex(int64(numCommitValue + 2*maxOutputNumberParam*maxExp), crypto.CStringBulletProof)

	gen.cs = append(gen.cs, csByteG...)
	gen.cs = append(gen.cs, csByteH...)
	gen.cs = append(gen.cs, gen.u.ToBytesS()...)

	return gen
}

func generateChallenge(values [][]byte) *crypto.Scalar {
	bytes := []byte{}
	for i := 0; i < len(values); i++ {
		bytes = append(bytes, values[i]...)
	}
	hash := crypto.HashToScalar(bytes)
	return hash
}

// EstimateAggBulletProofSize estimate aggregated bullet proof size
func EstimateAggBulletProofSize(nOutput int) uint64 {
	return uint64((nOutput+2*int(math.Log2(float64(maxExp*pad(nOutput))))+5)*crypto.Ed25519KeySize + 5*crypto.Ed25519KeySize + 2)
}


// pad returns number has format 2^k that it is the nearest number to num
func pad(num int) int {
	if num == 1 || num == 2 {
		return num
	}
	tmp := 2
	for i := 2; ; i++ {
		tmp *= 2
		if tmp >= num {
			num = tmp
			break
		}
	}
	return num
}

/*-----------------------------Vector Functions-----------------------------*/
// The length here always has to be a power of two

//vectorAdd adds two vector and returns result vector
func vectorAdd(a []*crypto.Scalar, b []*crypto.Scalar) ([]*crypto.Scalar, error) {
	if len(a) != len(b) {
		return nil, errors.New("VectorAdd: Arrays not of the same length")
	}

	res := make([]*crypto.Scalar, len(a))
	for i := range a {
		res[i] = new(crypto.Scalar).Add(a[i], b[i])
	}
	return res, nil
}

// innerProduct calculates inner product between two vectors a and b
func innerProduct(a []*crypto.Scalar, b []*crypto.Scalar) (*crypto.Scalar, error) {
	if len(a) != len(b) {
		return nil, errors.New("InnerProduct: Arrays not of the same length")
	}
	res := new(crypto.Scalar).FromUint64(uint64(0))
	for i := range a {
		//res = a[i]*b[i] + res % l
		res.MulAdd(a[i], b[i], res)
	}
	return res, nil
}

// hadamardProduct calculates hadamard product between two vectors a and b
func hadamardProduct(a []*crypto.Scalar, b []*crypto.Scalar) ([]*crypto.Scalar, error) {
	if len(a) != len(b) {
		return nil, errors.New("InnerProduct: Arrays not of the same length")
	}

	res := make([]*crypto.Scalar, len(a))
	for i := 0; i < len(res); i++ {
		res[i] = new(crypto.Scalar).Mul(a[i], b[i])
	}
	return res, nil
}

// powerVector calculates base^n
func powerVector(base *crypto.Scalar, n int) []*crypto.Scalar {
	res := make([]*crypto.Scalar, n)
	res[0] = new(crypto.Scalar).FromUint64(1)
	if n > 1 {
		res[1] = new(crypto.Scalar).Set(base)
		for i := 2; i < n; i++ {
			res[i] = new(crypto.Scalar).Mul(res[i-1], base)
		}
	}
	return res
}

// vectorAddScalar adds a vector to a big int, returns big int array
func vectorAddScalar(v []*crypto.Scalar, s *crypto.Scalar) []*crypto.Scalar {
	res := make([]*crypto.Scalar, len(v))

	for i := range v {
		res[i] = new(crypto.Scalar).Add(v[i], s)
	}
	return res
}

// vectorMulScalar mul a vector to a big int, returns a vector
func vectorMulScalar(v []*crypto.Scalar, s *crypto.Scalar) []*crypto.Scalar {
	res := make([]*crypto.Scalar, len(v))

	for i := range v {
		res[i] = new(crypto.Scalar).Mul(v[i], s)
	}
	return res
}

// encodeVectors encodes two value vectors l, r with two base point vectors g, h
func encodeVectors(l []*crypto.Scalar, r []*crypto.Scalar, g []*crypto.Point, h []*crypto.Point) (*crypto.Point, error) {
	if len(l) != len(r) || len(g) != len(l) || len(h) != len(g) {
		return nil, errors.New("invalid input")
	}
	tmp1 := new(crypto.Point).MultiScalarMult(l, g)
	tmp2 := new(crypto.Point).MultiScalarMult(r, h)

	res := new(crypto.Point).Add(tmp1, tmp2)
	return res, nil
}