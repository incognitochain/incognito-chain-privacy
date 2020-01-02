package bulletproof

import (
	"errors"
	"fmt"
	"github.com/incognitochain/incognito-chain-privacy/crypto"
)

/* Bullet proof convinces the verifier
that a commitment V contains a number v that is in a certain range, without revealing v.

See reference: https://eprint.iacr.org/2017/1066.pdf (Chapter 4.1 and 4.2)
*/

// Prove that each v in values is in [0, 2^N -1], N = maxExp = 64
type BulletWitness struct {
	values []uint64
	rands  []*crypto.Scalar
}

type BulletProof struct {
	comValues         []*crypto.Point
	a                 *crypto.Point
	s                 *crypto.Point
	t1                *crypto.Point
	t2                *crypto.Point
	tauX              *crypto.Scalar
	tHat              *crypto.Scalar
	mu                *crypto.Scalar
	innerProductProof *InnerProductProof
}

func (wit *BulletWitness) Set(values []uint64, rands []*crypto.Scalar) {
	numValue := len(values)
	wit.values = make([]uint64, numValue)
	wit.rands = make([]*crypto.Scalar, numValue)

	for i := range values {
		wit.values[i] = values[i]
		wit.rands[i] = new(crypto.Scalar).Set(rands[i])
	}
}

func (proof BulletProof) ValidateSanity() bool {
	for i := 0; i < len(proof.comValues); i++ {
		if !proof.comValues[i].PointValid() {
			return false
		}
	}
	if !proof.a.PointValid() {
		return false
	}
	if !proof.s.PointValid() {
		return false
	}
	if !proof.t1.PointValid() {
		return false
	}
	if !proof.t2.PointValid() {
		return false
	}
	if !proof.tauX.ScalarValid() {
		return false
	}
	if !proof.tHat.ScalarValid() {
		return false
	}
	if !proof.mu.ScalarValid() {
		return false
	}

	return proof.innerProductProof.ValidateSanity()
}

func (proof *BulletProof) Init() {
	proof.a = new(crypto.Point).Identity()
	proof.s = new(crypto.Point).Identity()
	proof.t1 = new(crypto.Point).Identity()
	proof.t2 = new(crypto.Point).Identity()
	proof.tauX = new(crypto.Scalar)
	proof.tHat = new(crypto.Scalar)
	proof.mu = new(crypto.Scalar)
	proof.innerProductProof = new(InnerProductProof)
}

func (proof BulletProof) IsNil() bool {
	if proof.a == nil {
		return true
	}
	if proof.s == nil {
		return true
	}
	if proof.t1 == nil {
		return true
	}
	if proof.t2 == nil {
		return true
	}
	if proof.tauX == nil {
		return true
	}
	if proof.tHat == nil {
		return true
	}
	if proof.mu == nil {
		return true
	}
	return proof.innerProductProof == nil
}

func (proof BulletProof) Bytes() []byte {
	var res []byte

	if proof.IsNil() {
		return []byte{}
	}

	res = append(res, byte(len(proof.comValues)))
	for i := 0; i < len(proof.comValues); i++ {
		res = append(res, proof.comValues[i].ToBytes()...)
	}

	res = append(res, proof.a.ToBytes()...)
	res = append(res, proof.s.ToBytes()...)
	res = append(res, proof.t1.ToBytes()...)
	res = append(res, proof.t2.ToBytes()...)

	res = append(res, proof.tauX.ToBytes()...)
	res = append(res, proof.tHat.ToBytes()...)
	res = append(res, proof.mu.ToBytes()...)
	res = append(res, proof.innerProductProof.Bytes()...)

	return res

}

func (proof *BulletProof) SetBytes(bytes []byte) error {
	if len(bytes) == 0 {
		return nil
	}

	lenValues := int(bytes[0])
	offset := 1
	var err error

	proof.comValues = make([]*crypto.Point, lenValues)
	for i := 0; i < lenValues; i++ {
		proof.comValues[i], err = new(crypto.Point).FromBytes(bytes[offset : offset+crypto.Ed25519KeySize])
		if err != nil {
			return err
		}
		offset += crypto.Ed25519KeySize
	}

	proof.a, err = new(crypto.Point).FromBytes(bytes[offset : offset+crypto.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += crypto.Ed25519KeySize

	proof.s, err = new(crypto.Point).FromBytes(bytes[offset : offset+crypto.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += crypto.Ed25519KeySize

	proof.t1, err = new(crypto.Point).FromBytes(bytes[offset : offset+crypto.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += crypto.Ed25519KeySize

	proof.t2, err = new(crypto.Point).FromBytes(bytes[offset : offset+crypto.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += crypto.Ed25519KeySize

	proof.tauX, err = new(crypto.Scalar).FromBytes(bytes[offset : offset+crypto.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += crypto.Ed25519KeySize

	proof.tHat, err = new(crypto.Scalar).FromBytes(bytes[offset : offset+crypto.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += crypto.Ed25519KeySize

	proof.mu, err = new(crypto.Scalar).FromBytes(bytes[offset : offset+crypto.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += crypto.Ed25519KeySize

	proof.innerProductProof = new(InnerProductProof)
	proof.innerProductProof.SetBytes(bytes[offset:])

	//crypto.Logger.Log.Debugf("AFTER SETBYTES ------------ %v\n", proof.Bytes())
	return nil
}

// Single_Prove creates bullet proof with one element in values array
func (wit *BulletWitness) Single_Prove() (*BulletProof, error) {
	// check witness
	if len(wit.values) != len(wit.rands) || len(wit.values) != 1 {
		return nil, errors.New("invalid witness of bullet protocol")
	}

	n := maxExp

	value := wit.values[0]
	valueInt := new(crypto.Scalar).FromUint64(value)
	rand := wit.rands[0]

	// compute V = G^v * H^r
	comValue := new(crypto.Point).AddPedersenBase(valueInt, rand)

	// Convert value to binary array aL
	// aR = aL - 1
	// PAPER LINES 41 - 42
	aL := crypto.ConvertUint64ToBinary(value, n)
	aR := make([]*crypto.Scalar, n)
	for i := 0; i < n; i++ {
		aR[i] = new(crypto.Scalar).Sub(aL[i], new(crypto.Scalar).FromUint64(1))
	}

	// PAPER LINES 43 - 44

	// generate random alpha
	alpha := crypto.RandomScalar()

	// Commitment to aL, aR: A = h^alpha * G^aL * H^aR
	A, err := encodeVectors(aL, aR, SingleBulletParam.g, SingleBulletParam.h)
	if err != nil {
		return nil, err
	}
	A.Add(A, new(crypto.Point).ScalarMult(crypto.H, alpha))


	// PAPER LINES 45 - 47
	// generate random blinding vectors sL, sR
	sL := make([]*crypto.Scalar, n)
	sR := make([]*crypto.Scalar, n)
	for i := range sL {
		sL[i] = crypto.RandomScalar()
		sR[i] = crypto.RandomScalar()
	}
	// generate random rho
	rho := crypto.RandomScalar()

	// commitment to sL, sR
	S, err := encodeVectors(sL, sR, SingleBulletParam.g, SingleBulletParam.h)
	if err != nil {
		return nil, err
	}
	S.Add(S, new(crypto.Point).ScalarMult(crypto.H, rho))

	// PAPER LINES 48 - 50
	// challenge y = H(csHash || comValue || A || S)
	// challenge z = H(csHash || comValue || A || S || y)
	y := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), A.ToBytes(), S.ToBytes()})
	z := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), A.ToBytes(), S.ToBytes(), y.ToBytes()})

	zNeg := new(crypto.Scalar).Sub(new(crypto.Scalar).FromUint64(0), z)
	zSquare := new(crypto.Scalar).Mul(z, z)
	zCube := new(crypto.Scalar).Mul(zSquare, z)

	// calculate polynomial l(X) and r(X)

	// l(X) = (aL - z*1^n) + sL*X = l0 + l1*X
	yVector := powerVector(y, n)
	twoNumber := new(crypto.Scalar).FromUint64(2)
	twoVector := powerVector(twoNumber, n)

	l0 := vectorAddScalar(aL, zNeg)
	l1 := sL

	// r(X) = y^n hada (aR + z*1^n + sR*X) + z^2 * 2^n = y^n hada (aR + z*1^n) + z^2 * 2^n  + (y^n hada * sR) * X = r0 + r1*X
	// r00 = y^n hada (aR + z*1^n) + z^2 * 2^n
	r00, err := hadamardProduct(yVector, vectorAddScalar(aR, z))
	if err != nil {
		return nil, err
	}

	// r01 = z^2 * 2^n
	r01 := vectorMulScalar(twoVector, zSquare)

	r0, err := vectorAdd(r00, r01)
	if err != nil {
		return nil, err
	}

	// r1 = y^n hada * sR
	r1, err := hadamardProduct(yVector, sR)
	if err != nil {
		return nil, err
	}

	// t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2

	// calculate t0 = v*z^2 + delta(y, z)
	// cal delta(y,z) = (z-z^2)* <1^n, y^n> - z^3* <1^n, 2^n>
	deltaYZ := new(crypto.Scalar).Sub(z, zSquare)

	// innerProduct1 = <1^n, y^n>
	innerProduct1 := new(crypto.Scalar).FromUint64(0)
	for i := 0; i < n; i++ {
		innerProduct1.Add(innerProduct1, yVector[i])
	}
	//innerProduct1 := innerProduct()

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2 := new(crypto.Scalar).FromUint64(0)
	for i := 0; i < n; i++ {
		innerProduct2.Add(innerProduct2, twoVector[i])
	}

	deltaYZ.Sub(deltaYZ, new(crypto.Scalar).Mul(zCube, innerProduct2))

	// t1 = <l1, r0> + <l0, r1>
	innerProduct3, err := innerProduct(l1, r0)
	if err != nil {
		return nil, err
	}
	innerProduct4, err := innerProduct(l0, r1)
	if err != nil {
		return nil, err
	}
	t1 := new(crypto.Scalar).Add(innerProduct3, innerProduct4)

	// t2 = <l1, r1>
	t2, err := innerProduct(l1, r1)
	if err != nil {
		return nil, err
	}

	// PAPER LINES 51 - 53
	// commitment to t1, t2
	tau1 := crypto.RandomScalar()
	tau2 := crypto.RandomScalar()

	T1 := new(crypto.Point).AddPedersenBase(t1, tau1)
	T2 := new(crypto.Point).AddPedersenBase(t2, tau2)

	// PAPER LINES 54 - 56
	// generate challenge x = H(csHash || comValue || A || S || T1 || T2)
	x := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), A.ToBytes(), S.ToBytes(), T1.ToBytes(), T2.ToBytes()})
	xSquare := new(crypto.Scalar).Mul(x, x)

	// PAPER LINES 58 - 62
	// lVector = aL - z*1^n + sL*x
	lVector, err := vectorAdd(vectorAddScalar(aL, zNeg), vectorMulScalar(sL, x))
	if err != nil {
		return nil, err
	}

	// rVector = y^n hada (aR + z*1^n + sR*x) + z^2*2^n
	tmpVector, err := vectorAdd(vectorAddScalar(aR, z), vectorMulScalar(sR, x))
	if err != nil {
		return nil, err
	}
	rVector, err := hadamardProduct(yVector, tmpVector)
	if err != nil {
		return nil, err
	}
	rVector, err = vectorAdd(rVector, vectorMulScalar(twoVector, zSquare))
	if err != nil {
		return nil, err
	}

	// tHat = <lVector, rVector>
	tHat, err := innerProduct(lVector, rVector)
	if err != nil {
		return nil, err
	}

	// blinding value for tHat: tauX = tau2*x^2 + tau1*x + z^2*rand
	tauX :=  new(crypto.Scalar).Add(new(crypto.Scalar).Mul(tau2, xSquare), new(crypto.Scalar).Mul(tau1, x))
	tauX.Add(tauX, new(crypto.Scalar).Mul(zSquare, rand))

	// alpha, rho blind A, S
	// mu = alpha + rho*x
	mu := new(crypto.Scalar).Add(alpha, new(crypto.Scalar).Mul(rho, x))

	// instead of sending left vector and right vector, we use inner sum argument to reduce proof size from 2*n to 2(log2(n)) + 2

	// calculate HPrime = H^(y^(-n))
	HPrime := make([]*crypto.Point, n)
	yInverse := new(crypto.Scalar).Invert(y)
	expYInverse := new(crypto.Scalar).FromUint64(1)
	for i := 0; i < n; i++ {
		HPrime[i] = new(crypto.Point).ScalarMult(SingleBulletParam.h[i], expYInverse)
		expYInverse.Mul(expYInverse, yInverse)
	}

	newParam, err := setBulletproofParams(SingleBulletParam.g, HPrime)
	if err != nil {
		return nil, err
	}

	innerProductWit := new(InnerProductWitness)
	innerProductWit.a = lVector
	innerProductWit.b = rVector
	innerProductWit.p, err = encodeVectors(lVector, rVector, newParam.g, newParam.h)
	if err != nil {
		return nil, err
	}
	innerProductWit.p = innerProductWit.p.Add(innerProductWit.p, new(crypto.Point).ScalarMult(SingleBulletParam.u, tHat))

	innerProductProof, err := innerProductWit.Prove(newParam)
	if err != nil {
		return nil, err
	}

	proof := BulletProof{
		comValues: []*crypto.Point{comValue},
		a: A,
		s: S,
		t1: T1,
		t2: T2,
		tauX: tauX,
		tHat: tHat,
		mu: mu,
		innerProductProof: innerProductProof,
	}

	return &proof, nil
}

func (proof BulletProof) Single_Verify() (bool, error) {
	numValue := len(proof.comValues)

	if numValue != 1 {
		return false, errors.New("number of output coins must be equal 1")
	}

	n := maxExp
	comValue := proof.comValues[0]

	twoNumber := new(crypto.Scalar).FromUint64(2)
	twoVector := powerVector(twoNumber, n)

	// recalculate challenge y, z
	// challenge y = H(csHash || comValue || A || S)
	// challenge z = H(csHash || comValue || A || S || y)
	y := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), proof.a.ToBytes(), proof.s.ToBytes()})
	z := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), proof.a.ToBytes(), proof.s.ToBytes(), y.ToBytes()})

	zSquare := new(crypto.Scalar).Mul(z, z)
	zCube := new(crypto.Scalar).Mul(zSquare, z)

	// recalculate challenge x = H(csHash || comValue || A || S || T1 || T2)
	x := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), proof.a.ToBytes(), proof.s.ToBytes(), proof.t1.ToBytes(), proof.t2.ToBytes()})
	xSquare := new(crypto.Scalar).Mul(x, x)

	yVector := powerVector(y, n)

	// PAPER LINE 65
	// check the first statement
	// g^tHat * h^tauX == comValue^(z^2) * g^delta(y, z) * T1^x * T2^(x^2)

	// cal delta(y,z) = (z-z^2)* <1^n, y^n> - z^3* <1^n, 2^n>
	deltaYZ := new(crypto.Scalar).Sub(z, zSquare)

	// innerProduct1 = <1^n, y^n>
	innerProduct1 := new(crypto.Scalar).FromUint64(0)
	for i := 0; i < n; i++ {
		innerProduct1.Add(innerProduct1, yVector[i])
	}

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2 := new(crypto.Scalar).FromUint64(0)
	for i := 0; i < n; i++ {
		innerProduct2.Add(innerProduct2, twoVector[i])
	}

	deltaYZ.Sub(deltaYZ, new(crypto.Scalar).Mul(zCube, innerProduct2))

	left1 := new(crypto.Point).AddPedersenBase(proof.tHat, proof.tauX)

	right1 := new(crypto.Point).Add(new(crypto.Point).ScalarMult(comValue, zSquare), new(crypto.Point).ScalarMultBase(deltaYZ))
	right1.Add(right1, new(crypto.Point).AddPedersen(x, proof.t1, xSquare, proof.t2))

	if !crypto.IsPointEqual(left1, right1) {
		fmt.Printf("verify aggregated range proof statement 1 failed")
		return false, errors.New("verify aggregated range proof statement 1 failed")
	}

	// PAPER LINE 64
	// calculate HPrime = H^(y^(-n))
	HPrime := make([]*crypto.Point, n)
	yInverse := new(crypto.Scalar).Invert(y)
	expYInverse := new(crypto.Scalar).FromUint64(1)
	for i := 0; i < n; i++ {
		HPrime[i] = new(crypto.Point).ScalarMult(SingleBulletParam.h[i], expYInverse)
		expYInverse.Mul(expYInverse, yInverse)
	}

	newParam, err := setBulletproofParams(SingleBulletParam.g, HPrime)
	if err != nil {
		return false, err
	}

	innerProductArgValid := proof.innerProductProof.Verify(newParam)
	if !innerProductArgValid {
		fmt.Printf("verify aggregated range proof statement 2 failed")
		return false, errors.New("verify aggregated range proof statement 2 failed")
	}

	return true, nil
}

func (proof BulletProof) Single_Verify_Fast() (bool, error) {
	numValue := len(proof.comValues)

	if numValue != 1 {
		return false, errors.New("number of output coins must be equal 1")
	}

	n := maxExp
	comValue := proof.comValues[0]

	twoNumber := new(crypto.Scalar).FromUint64(2)
	twoVector := powerVector(twoNumber, n)

	// recalculate challenge y, z
	// challenge y = H(csHash || comValue || A || S)
	// challenge z = H(csHash || comValue || A || S || y)
	y := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), proof.a.ToBytes(), proof.s.ToBytes()})
	z := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), proof.a.ToBytes(), proof.s.ToBytes(), y.ToBytes()})

	zSquare := new(crypto.Scalar).Mul(z, z)
	zCube := new(crypto.Scalar).Mul(zSquare, z)

	// recalculate challenge x = H(csHash || comValue || A || S || T1 || T2)
	x := generateChallenge([][]byte{SingleBulletParam.cs, comValue.ToBytes(), proof.a.ToBytes(), proof.s.ToBytes(), proof.t1.ToBytes(), proof.t2.ToBytes()})
	xSquare := new(crypto.Scalar).Mul(x, x)

	yVector := powerVector(y, n)

	// PAPER LINE 65
	// check the first statement
	// g^tHat * h^tauX == comValue^(z^2) * g^delta(y, z) * T1^x * T2^(x^2)

	// cal delta(y,z) = (z-z^2)* <1^n, y^n> - z^3* <1^n, 2^n>
	deltaYZ := new(crypto.Scalar).Sub(z, zSquare)

	// innerProduct1 = <1^n, y^n>
	innerProduct1 := new(crypto.Scalar).FromUint64(0)
	for i := 0; i < n; i++ {
		innerProduct1.Add(innerProduct1, yVector[i])
	}

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2 := new(crypto.Scalar).FromUint64(0)
	for i := 0; i < n; i++ {
		innerProduct2.Add(innerProduct2, twoVector[i])
	}

	deltaYZ.Sub(deltaYZ, new(crypto.Scalar).Mul(zCube, innerProduct2))

	left1 := new(crypto.Point).AddPedersenBase(proof.tHat, proof.tauX)

	right1 := new(crypto.Point).Add(new(crypto.Point).ScalarMult(comValue, zSquare), new(crypto.Point).ScalarMultBase(deltaYZ))
	right1.Add(right1, new(crypto.Point).AddPedersen(x, proof.t1, xSquare, proof.t2))

	if !crypto.IsPointEqual(left1, right1) {
		fmt.Printf("verify aggregated range proof statement 1 failed")
		return false, errors.New("verify aggregated range proof statement 1 failed")
	}

	// PAPER LINE 64
	// calculate HPrime = H^(y^(-n))
	HPrime := make([]*crypto.Point, n)
	yInverse := new(crypto.Scalar).Invert(y)
	expYInverse := new(crypto.Scalar).FromUint64(1)
	for i := 0; i < n; i++ {
		HPrime[i] = new(crypto.Point).ScalarMult(SingleBulletParam.h[i], expYInverse)
		expYInverse.Mul(expYInverse, yInverse)
	}

	newParam, err := setBulletproofParams(SingleBulletParam.g, HPrime)
	if err != nil {
		return false, err
	}

	innerProductArgValid := proof.innerProductProof.Verify_Fast(newParam)
	if !innerProductArgValid {
		fmt.Printf("verify aggregated range proof statement 2 failed")
		return false, errors.New("verify aggregated range proof statement 2 failed")
	}

	return true, nil
}

// Single_Prove creates bullet proof with multi elements in values array
func (wit *BulletWitness) Agg_Prove() (*BulletProof, error) {
	proof := new(BulletProof)

	numValue := len(wit.values)
	if numValue > maxNOut {
		return nil, errors.New("Must less than maxNOut")
	}
	numValuePad := pad(numValue)

	aggParam := getBulletproofParams(numValuePad)

	values := make([]uint64, numValuePad)
	rands := make([]*crypto.Scalar, numValuePad)

	for i := range wit.values {
		values[i] = wit.values[i]
		rands[i] = new(crypto.Scalar).Set(wit.rands[i])
	}

	for i := numValue; i < numValuePad; i++ {
		values[i] = uint64(0)
		rands[i] = new(crypto.Scalar).FromUint64(0)
	}

	proof.comValues = make([]*crypto.Point, numValue)
	for i := 0; i < numValue; i++ {
		proof.comValues[i] = new(crypto.Point).AddPedersenBase(new(crypto.Scalar).FromUint64(values[i]), rands[i])
	}

	n := maxExp
	// Convert values to binary array
	aL := make([]*crypto.Scalar, numValuePad*n)
	for i, value := range values {
		tmp := crypto.ConvertUint64ToBinary(value, n)
		for j := 0; j < n; j++ {
			aL[i*n+j] = tmp[j]
		}
	}

	twoNumber := new(crypto.Scalar).FromUint64(2)
	twoVectorN := powerVector(twoNumber, n)

	aR := make([]*crypto.Scalar, numValuePad*n)

	for i := 0; i < numValuePad*n; i++ {
		aR[i] = new(crypto.Scalar).Sub(aL[i], new(crypto.Scalar).FromUint64(1))
	}

	// random alpha
	alpha := crypto.RandomScalar()

	// Commitment to aL, aR: A = h^alpha * G^aL * H^aR
	A, err := encodeVectors(aL, aR, aggParam.g, aggParam.h)
	if err != nil {
		return nil, err
	}
	A.Add(A, new(crypto.Point).ScalarMult(crypto.H, alpha))
	proof.a = A

	// Random blinding vectors sL, sR
	sL := make([]*crypto.Scalar, n*numValuePad)
	sR := make([]*crypto.Scalar, n*numValuePad)
	for i := range sL {
		sL[i] = crypto.RandomScalar()
		sR[i] = crypto.RandomScalar()
	}

	// random rho
	rho := crypto.RandomScalar()

	// Commitment to sL, sR : S = h^rho * G^sL * H^sR
	S, err := encodeVectors(sL, sR, aggParam.g, aggParam.h)
	if err != nil {
		return nil, err
	}
	S.Add(S, new(crypto.Point).ScalarMult(crypto.H, rho))
	proof.s = S

	// challenge y, z
	y := generateChallenge([][]byte{aggParam.cs, A.ToBytes(), S.ToBytes()})
	z := generateChallenge([][]byte{aggParam.cs, A.ToBytes(), S.ToBytes(), y.ToBytes()})

	zNeg := new(crypto.Scalar).Sub(new(crypto.Scalar).FromUint64(0), z)
	zSquare := new(crypto.Scalar).Mul(z, z)

	// l(X) = (aL -z*1^n) + sL*X
	yVector := powerVector(y, n*numValuePad)

	l0 := vectorAddScalar(aL, zNeg)
	l1 := sL

	// r(X) = y^n hada (aR +z*1^n + sR*X) + z^2 * 2^n
	hadaProduct, err := hadamardProduct(yVector, vectorAddScalar(aR, z))
	if err != nil {
		return nil, err
	}

	vectorSum := make([]*crypto.Scalar, n*numValuePad)
	zTmp := new(crypto.Scalar).Set(z)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		for i := 0; i < n; i++ {
			vectorSum[j*n+i] = new(crypto.Scalar).Mul(twoVectorN[i], zTmp)
		}
	}

	r0, err := vectorAdd(hadaProduct, vectorSum)
	if err != nil {
		return nil, err
	}

	r1, err := hadamardProduct(yVector, sR)
	if err != nil {
		return nil, err
	}

	//t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2

	//calculate t0 = v*z^2 + delta(y, z)
	deltaYZ := new(crypto.Scalar).Sub(z, zSquare)

	// innerProduct1 = <1^(n*m), y^(n*m)>
	innerProduct1 := new(crypto.Scalar).FromUint64(0)
	for i := 0; i < n*numValuePad; i++ {
		innerProduct1.Add(innerProduct1, yVector[i])
	}

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2 := new(crypto.Scalar).FromUint64(0)
	for i := 0; i < n; i++ {
		innerProduct2.Add(innerProduct2, twoVectorN[i])
	}

	sum := new(crypto.Scalar).FromUint64(0)
	zTmp = new(crypto.Scalar).Set(zSquare)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		sum.Add(sum, zTmp)
	}
	sum.Mul(sum, innerProduct2)
	deltaYZ.Sub(deltaYZ, sum)

	// t1 = <l1, r0> + <l0, r1>
	innerProduct3, err := innerProduct(l1, r0)
	if err != nil {
		return nil, err
	}

	innerProduct4, err := innerProduct(l0, r1)
	if err != nil {
		return nil, err
	}

	t1 := new(crypto.Scalar).Add(innerProduct3, innerProduct4)

	// t2 = <l1, r1>
	t2, err := innerProduct(l1, r1)
	if err != nil {
		return nil, err
	}

	// commitment to t1, t2
	tau1 := crypto.RandomScalar()
	tau2 := crypto.RandomScalar()

	proof.t1 = new(crypto.Point).AddPedersenBase(t1, tau1)
	proof.t2 = new(crypto.Point).AddPedersenBase(t2, tau2)

	// challenge x = hash(G || H || A || S || T1 || T2)
	x := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytes(), proof.s.ToBytes(), proof.t1.ToBytes(), proof.t2.ToBytes()})

	xSquare := new(crypto.Scalar).Mul(x, x)

	// lVector = aL - z*1^n + sL*x
	lVector, err := vectorAdd(vectorAddScalar(aL, zNeg), vectorMulScalar(sL, x))
	if err != nil {
		return nil, err
	}

	// rVector = y^n hada (aR +z*1^n + sR*x) + z^2*2^n
	tmpVector, err := vectorAdd(vectorAddScalar(aR, z), vectorMulScalar(sR, x))
	if err != nil {
		return nil, err
	}
	rVector, err := hadamardProduct(yVector, tmpVector)
	if err != nil {
		return nil, err
	}

	vectorSum = make([]*crypto.Scalar, n*numValuePad)
	zTmp = new(crypto.Scalar).Set(z)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		for i := 0; i < n; i++ {
			vectorSum[j*n+i] = new(crypto.Scalar).Mul(twoVectorN[i], zTmp)
		}
	}

	rVector, err = vectorAdd(rVector, vectorSum)
	if err != nil {
		return nil, err
	}

	// tHat = <lVector, rVector>
	proof.tHat, err = innerProduct(lVector, rVector)
	if err != nil {
		return nil, err
	}

	// blinding value for tHat: tauX = tau2*x^2 + tau1*x + z^2*rand
	proof.tauX = new(crypto.Scalar).Mul(tau2, xSquare)
	proof.tauX.Add(proof.tauX, new(crypto.Scalar).Mul(tau1, x))
	zTmp = new(crypto.Scalar).Set(z)
	tmpBN := new(crypto.Scalar)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		proof.tauX.Add(proof.tauX, tmpBN.Mul(zTmp, rands[j]))
	}

	// alpha, rho blind A, S
	// mu = alpha + rho*x
	proof.mu = new(crypto.Scalar).Mul(rho, x)
	proof.mu.Add(proof.mu, alpha)

	// instead of sending left vector and right vector, we use inner sum argument to reduce proof size from 2*n to 2(log2(n)) + 2
	innerProductWit := new(InnerProductWitness)
	innerProductWit.a = lVector
	innerProductWit.b = rVector
	innerProductWit.p, err = encodeVectors(lVector, rVector, aggParam.g, aggParam.h)
	if err != nil {
		return nil, err
	}
	innerProductWit.p = innerProductWit.p.Add(innerProductWit.p, new(crypto.Point).ScalarMult(aggParam.u, proof.tHat))

	proof.innerProductProof, err = innerProductWit.Prove(aggParam)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

func (proof BulletProof) Agg_Verify() (bool, error) {
	numValue := len(proof.comValues)
	if numValue > maxNOut {
		return false, errors.New("Must less than maxNOut")
	}
	numValuePad := pad(numValue)
	aggParam := getBulletproofParams(numValuePad)

	tmpcmsValue := proof.comValues
	for i := numValue; i < numValuePad; i++ {
		identity := new(crypto.Point).Identity()
		tmpcmsValue = append(tmpcmsValue, identity)
	}

	n := maxExp
	oneNumber := new(crypto.Scalar).FromUint64(1)
	twoNumber := new(crypto.Scalar).FromUint64(2)
	oneVector := powerVector(oneNumber, n*numValuePad)
	oneVectorN := powerVector(oneNumber, n)
	twoVectorN := powerVector(twoNumber, n)

	// recalculate challenge y, z
	y := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytes(), proof.s.ToBytes()})
	z := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytes(), proof.s.ToBytes(), y.ToBytes()})

	zSquare := new(crypto.Scalar).Mul(z, z)

	// challenge x = hash(G || H || A || S || T1 || T2)
	//fmt.Printf("T2: %v\n", proof.t2)
	x := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytes(), proof.s.ToBytes(), proof.t1.ToBytes(), proof.t2.ToBytes()})

	xSquare := new(crypto.Scalar).Mul(x, x)

	yVector := powerVector(y, n*numValuePad)
	// HPrime = H^(y^(1-i)
	HPrime := make([]*crypto.Point, n*numValuePad)
	yInverse := new(crypto.Scalar).Invert(y)
	expyInverse := new(crypto.Scalar).FromUint64(1)
	for i := 0; i < n*numValuePad; i++ {
		HPrime[i] = new(crypto.Point).ScalarMult(aggParam.h[i], expyInverse)
		expyInverse.Mul(expyInverse, yInverse)
	}

	// g^tHat * h^tauX = V^(z^2) * g^delta(y,z) * T1^x * T2^(x^2)
	deltaYZ := new(crypto.Scalar).Sub(z, zSquare)

	// innerProduct1 = <1^(n*m), y^(n*m)>
	innerProduct1, err := innerProduct(oneVector, yVector)
	if err != nil {
		return false, err
	}

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2, err := innerProduct(oneVectorN, twoVectorN)
	if err != nil {
		return false, err
	}

	sum := new(crypto.Scalar).FromUint64(0)
	zTmp := new(crypto.Scalar).Set(zSquare)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		sum.Add(sum, zTmp)
	}
	sum.Mul(sum, innerProduct2)
	deltaYZ.Sub(deltaYZ, sum)

	left1 := new(crypto.Point).AddPedersenBase(proof.tHat, proof.tauX)

	right1 := new(crypto.Point).ScalarMult(proof.t2, xSquare)
	right1.Add(right1, new(crypto.Point).AddPedersen(deltaYZ, crypto.G, x, proof.t1))

	expVector := vectorMulScalar(powerVector(z, numValuePad), zSquare)
	right1.Add(right1, new(crypto.Point).MultiScalarMult(expVector, tmpcmsValue))

	if !crypto.IsPointEqual(left1, right1) {
		fmt.Printf("verify aggregated range proof statement 1 failed")
		return false, errors.New("verify aggregated range proof statement 1 failed")
	}

	innerProductArgValid := proof.innerProductProof.Verify(aggParam)
	if !innerProductArgValid {
		fmt.Printf("verify aggregated range proof statement 2 failed")
		return false, errors.New("verify aggregated range proof statement 2 failed")
	}

	return true, nil
}

func (proof BulletProof) Agg_Verify_Fast() (bool, error) {
	numValue := len(proof.comValues)
	if numValue > maxNOut {
		return false, errors.New("Must less than maxNOut")
	}
	numValuePad := pad(numValue)
	aggParam := getBulletproofParams(numValuePad)

	tmpcmsValue := proof.comValues

	for i := numValue; i < numValuePad; i++ {
		identity := new(crypto.Point).Identity()
		tmpcmsValue = append(tmpcmsValue, identity)
	}

	n := maxExp
	oneNumber := new(crypto.Scalar).FromUint64(1)
	twoNumber := new(crypto.Scalar).FromUint64(2)
	oneVector := powerVector(oneNumber, n*numValuePad)
	oneVectorN := powerVector(oneNumber, n)
	twoVectorN := powerVector(twoNumber, n)

	// recalculate challenge y, z
	y := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytes(), proof.s.ToBytes()})
	z := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytes(), proof.s.ToBytes(), y.ToBytes()})
	zSquare := new(crypto.Scalar).Mul(z, z)

	// challenge x = hash(G || H || A || S || T1 || T2)
	//fmt.Printf("T2: %v\n", proof.t2)
	x := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytes(), proof.s.ToBytes(), proof.t1.ToBytes(), proof.t2.ToBytes()})
	xSquare := new(crypto.Scalar).Mul(x, x)

	yVector := powerVector(y, n*numValuePad)
	// HPrime = H^(y^(1-i)
	HPrime := make([]*crypto.Point, n*numValuePad)
	yInverse := new(crypto.Scalar).Invert(y)
	expyInverse := new(crypto.Scalar).FromUint64(1)
	for i := 0; i < n*numValuePad; i++ {
		HPrime[i] = new(crypto.Point).ScalarMult(aggParam.h[i], expyInverse)
		expyInverse.Mul(expyInverse, yInverse)
	}

	// g^tHat * h^tauX = V^(z^2) * g^delta(y,z) * T1^x * T2^(x^2)
	deltaYZ := new(crypto.Scalar).Sub(z, zSquare)

	// innerProduct1 = <1^(n*m), y^(n*m)>
	innerProduct1, err := innerProduct(oneVector, yVector)
	if err != nil {
		return false, err
	}

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2, err := innerProduct(oneVectorN, twoVectorN)
	if err != nil {
		return false, err
	}

	sum := new(crypto.Scalar).FromUint64(0)
	zTmp := new(crypto.Scalar).Set(zSquare)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		sum.Add(sum, zTmp)
	}
	sum.Mul(sum, innerProduct2)
	deltaYZ.Sub(deltaYZ, sum)

	left1 := new(crypto.Point).AddPedersenBase(proof.tHat, proof.tauX)

	right1 := new(crypto.Point).ScalarMult(proof.t2, xSquare)
	right1.Add(right1, new(crypto.Point).AddPedersen(deltaYZ, crypto.G, x, proof.t1))

	expVector := vectorMulScalar(powerVector(z, numValuePad), zSquare)
	right1.Add(right1, new(crypto.Point).MultiScalarMult(expVector, tmpcmsValue))

	if !crypto.IsPointEqual(left1, right1) {
		fmt.Printf("verify aggregated range proof statement 1 failed")
		return false, errors.New("verify aggregated range proof statement 1 failed")
	}

	innerProductArgValid := proof.innerProductProof.Verify_Fast(aggParam)
	if !innerProductArgValid {
		fmt.Printf("verify aggregated range proof statement 2 failed")
		return false, errors.New("verify aggregated range proof statement 2 failed")
	}

	return true, nil
}
