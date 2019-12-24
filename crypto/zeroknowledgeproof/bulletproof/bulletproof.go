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

// Single_Prove creates bullet proof with one element in values array
func (wit *BulletWitness) Single_Prove() (*BulletProof, error) {
	// check witness
	if len(wit.values) != len(wit.rands) || len(wit.values) != 1 {
		return nil, errors.New("invalid witness of bullet protocol")
	}

	// todo:

	return nil, nil
}

// Single_Prove creates bullet proof with multi elements in values array
func (wit *BulletWitness) Agg_Prove() (*BulletProof, error) {
	proof := new(BulletProof)

	numValue := len(wit.values)
	if numValue > maxOutputNumber {
		return nil, errors.New("Must less than maxOutputNumber")
	}
	numValuePad := pad(numValue)
	aggParam := new(bulletproofParams)
	aggParam.g = AggParam.g[0 : numValuePad*maxExp]
	aggParam.h = AggParam.h[0 : numValuePad*maxExp]
	aggParam.u = AggParam.u
	csByteH := []byte{}
	csByteG := []byte{}
	for i := 0; i < len(aggParam.g); i++ {
		csByteG = append(csByteG, aggParam.g[i].ToBytesS()...)
		csByteH = append(csByteH, aggParam.h[i].ToBytesS()...)
	}
	aggParam.cs = append(aggParam.cs, csByteG...)
	aggParam.cs = append(aggParam.cs, csByteH...)
	aggParam.cs = append(aggParam.cs, aggParam.u.ToBytesS()...)

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
		proof.comValues[i] = new(crypto.Point).AddPedersenWithBasePoint(new(crypto.Scalar).FromUint64(values[i]), rands[i])
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
	y := generateChallenge([][]byte{aggParam.cs, A.ToBytesS(), S.ToBytesS()})
	z := generateChallenge([][]byte{aggParam.cs, A.ToBytesS(), S.ToBytesS(), y.ToBytesS()})

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

	proof.t1 = new(crypto.Point).AddPedersenWithBasePoint(t1, tau1)
	proof.t2 = new(crypto.Point).AddPedersenWithBasePoint(t2, tau2)

	// challenge x = hash(G || H || A || S || T1 || T2)
	x := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), proof.t1.ToBytesS(), proof.t2.ToBytesS()})

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
	if numValue > maxOutputNumber {
		return false, errors.New("Must less than maxOutputNumber")
	}
	numValuePad := pad(numValue)
	aggParam := new(bulletproofParams)
	aggParam.g = AggParam.g[0 : numValuePad*maxExp]
	aggParam.h = AggParam.h[0 : numValuePad*maxExp]
	aggParam.u = AggParam.u
	csByteH := []byte{}
	csByteG := []byte{}
	for i := 0; i < len(aggParam.g); i++ {
		csByteG = append(csByteG, aggParam.g[i].ToBytesS()...)
		csByteH = append(csByteH, aggParam.h[i].ToBytesS()...)
	}
	aggParam.cs = append(aggParam.cs, csByteG...)
	aggParam.cs = append(aggParam.cs, csByteH...)
	aggParam.cs = append(aggParam.cs, aggParam.u.ToBytesS()...)

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
	y := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS()})
	z := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), y.ToBytesS()})

	zSquare := new(crypto.Scalar).Mul(z, z)

	// challenge x = hash(G || H || A || S || T1 || T2)
	//fmt.Printf("T2: %v\n", proof.t2)
	x := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), proof.t1.ToBytesS(), proof.t2.ToBytesS()})

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

	left1 := new(crypto.Point).AddPedersenWithBasePoint(proof.tHat, proof.tauX)

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
	if numValue > maxOutputNumber {
		return false, errors.New("Must less than maxOutputNumber")
	}
	numValuePad := pad(numValue)
	aggParam := new(bulletproofParams)
	aggParam.g = AggParam.g[0 : numValuePad*maxExp]
	aggParam.h = AggParam.h[0 : numValuePad*maxExp]
	aggParam.u = AggParam.u
	csByteH := []byte{}
	csByteG := []byte{}
	for i := 0; i < len(aggParam.g); i++ {
		csByteG = append(csByteG, aggParam.g[i].ToBytesS()...)
		csByteH = append(csByteH, aggParam.h[i].ToBytesS()...)
	}
	aggParam.cs = append(aggParam.cs, csByteG...)
	aggParam.cs = append(aggParam.cs, csByteH...)
	aggParam.cs = append(aggParam.cs, aggParam.u.ToBytesS()...)

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
	y := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS()})
	z := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), y.ToBytesS()})
	zSquare := new(crypto.Scalar).Mul(z, z)

	// challenge x = hash(G || H || A || S || T1 || T2)
	//fmt.Printf("T2: %v\n", proof.t2)
	x := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), proof.t1.ToBytesS(), proof.t2.ToBytesS()})
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

	left1 := new(crypto.Point).AddPedersenWithBasePoint(proof.tHat, proof.tauX)

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
