package bulletproof

import (
	"errors"
	"github.com/incognitochain/incognito-chain-privacy/crypto"
	"math"
)

const (
	maxExp              = 64
	nOutPreComputeParam = 32
	maxNOut             = 32
	maxNOutParam        = 256
)

// bulletproofParams includes all generator for aggregated range proof
type bulletproofParams struct {
	g  []*crypto.Point
	h  []*crypto.Point
	u  *crypto.Point
	cs []byte
}

var BulletParam = newBulletproofParams(nOutPreComputeParam)
var SingleBulletParam = newBulletproofParams(1)

func newBulletproofParams(m int) *bulletproofParams {
	param := new(bulletproofParams)
	param.cs = []byte{}
	capacity := maxExp * m // fixed value
	maxCapacity := maxNOutParam * maxExp
	param.g = make([]*crypto.Point, capacity)
	param.h = make([]*crypto.Point, capacity)
	csByteH := []byte{}
	csByteG := []byte{}

	for i := 0; i < capacity; i++ {
		param.g[i] = crypto.HashToPointFromIndex(int64(i), crypto.CStringBulletProof)
		param.h[i] = crypto.HashToPointFromIndex(int64(i + maxCapacity), crypto.CStringBulletProof)
		csByteG = append(csByteG, param.g[i].ToBytesS()...)
		csByteH = append(csByteH, param.h[i].ToBytesS()...)
	}

	param.u = new(crypto.Point)
	param.u = crypto.HashToPointFromIndex(int64(2 * maxCapacity), crypto.CStringBulletProof)

	param.cs = append(param.cs, csByteG...)
	param.cs = append(param.cs, csByteH...)
	param.cs = append(param.cs, param.u.ToBytesS()...)
	param.cs = crypto.HashToScalar(param.cs).ToBytesS()

	return param
}

func getBulletproofParams(m int) *bulletproofParams {
	newParam := new(bulletproofParams)
	newParam.u = BulletParam.u
	newParam.cs = BulletParam.cs
	newParam.g = make([]*crypto.Point, m * maxExp)
	newParam.h = make([]*crypto.Point, m * maxExp)

	for i := range newParam.g {
		newParam.g[i] = new(crypto.Point).Set(BulletParam.g[i])
		newParam.h[i] = new(crypto.Point).Set(BulletParam.h[i])
	}

	return newParam
}

func setBulletproofParams(g []*crypto.Point, h []*crypto.Point) (*bulletproofParams, error) {
	if len(g) != len(h) {
		return nil, errors.New("invalid len param points")
	}
	newParam := new(bulletproofParams)
	newParam.u = BulletParam.u

	newParam.g = make([]*crypto.Point, len(g))
	newParam.h = make([]*crypto.Point, len(h))

	csBytes := []byte{}
	gBytes := []byte{}
	hBytes := []byte{}

	for i := range newParam.g {
		newParam.g[i] = new(crypto.Point).Set(BulletParam.g[i])
		newParam.h[i] = new(crypto.Point).Set(BulletParam.h[i])

		gBytes = append(gBytes, newParam.g[i].ToBytesS()...)
		hBytes = append(hBytes, newParam.h[i].ToBytesS()...)
	}

	csBytes = append(csBytes, gBytes...)
	csBytes = append(csBytes, hBytes...)
	csBytes = append(csBytes, newParam.u.ToBytesS()...)
	newParam.cs = crypto.HashToScalar(csBytes).ToBytesS()

	return newParam, nil
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