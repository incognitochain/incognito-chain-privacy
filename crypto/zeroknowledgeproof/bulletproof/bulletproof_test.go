package bulletproof

import (
	"fmt"
	"github.com/incognitochain/incognito-chain-privacy/crypto"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestPad(t *testing.T) {
	data := []struct {
		number       int
		paddedNumber int
	}{
		{1000, 1024},
		{3, 4},
		{5, 8},
	}

	for _, item := range data {
		num := pad(item.number)
		assert.Equal(t, item.paddedNumber, num)
	}
}

func TestPowerVector(t *testing.T) {
	twoVector := powerVector(new(crypto.Scalar).FromUint64(2), 5)
	assert.Equal(t, 5, len(twoVector))
}

func TestInnerProduct(t *testing.T) {
	for j := 0; j < 100; j++ {
		n := maxExp
		a := make([]*crypto.Scalar, n)
		b := make([]*crypto.Scalar, n)
		uinta := make([]uint64, n)
		uintb := make([]uint64, n)
		uintc := uint64(0)
		for i := 0; i < n; i++ {
			uinta[i] = uint64(rand.Intn(100000000))
			uintb[i] = uint64(rand.Intn(100000000))
			a[i] = new(crypto.Scalar).FromUint64(uinta[i])
			b[i] = new(crypto.Scalar).FromUint64(uintb[i])
			uintc += uinta[i] * uintb[i]
		}

		c, _ := innerProduct(a, b)
		assert.Equal(t, new(crypto.Scalar).FromUint64(uintc), c)
	}
}

func TestEncodeVectors(t *testing.T) {
	for i := 0; i < 100; i++ {
		var AggParam = newBulletproofParams(1)
		n := maxExp
		a := make([]*crypto.Scalar, n)
		b := make([]*crypto.Scalar, n)
		G := make([]*crypto.Point, n)
		H := make([]*crypto.Point, n)

		for i := range a {
			a[i] = crypto.RandomScalar()
			b[i] = crypto.RandomScalar()
			G[i] = new(crypto.Point).Set(AggParam.g[i])
			H[i] = new(crypto.Point).Set(AggParam.h[i])
		}

		actualRes, err := encodeVectors(a, b, G, H)
		if err != nil {
			fmt.Printf("Err: %v\n", err)
		}

		expectedRes := new(crypto.Point).Identity()
		for i := 0; i < n; i++ {
			expectedRes.Add(expectedRes, new(crypto.Point).ScalarMult(G[i], a[i]))
			expectedRes.Add(expectedRes, new(crypto.Point).ScalarMult(H[i], b[i]))
		}

		assert.Equal(t, expectedRes, actualRes)
	}
}

func TestAggregatedRangeProveVerify(t *testing.T) {
	for i := 0; i < 10; i++ {
		//prepare witness for Aggregated range protocol
		wit := new(BulletWitness)
		numValue := rand.Intn(maxOutputNumber)
		values := make([]uint64, numValue)
		rands := make([]*crypto.Scalar, numValue)

		for i := range values {
			values[i] = uint64(rand.Uint64())
			rands[i] = crypto.RandomScalar()
		}
		wit.Set(values, rands)

		// proving
		proof, err := wit.Agg_Prove()
		assert.Equal(t, nil, err)

		// verify the proof
		res, err := proof.Agg_Verify()
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)

		// verify the proof faster
		res, err = proof.Agg_Verify_Fast()
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)

		// validate sanity for proof
		isValidSanity := proof.ValidateSanity()
		assert.Equal(t, true, isValidSanity)

		// convert proof to bytes array
		bytes := proof.Bytes()
		expectProofSize := EstimateAggBulletProofSize(numValue)
		assert.Equal(t, int(expectProofSize), len(bytes))

		// new aggregatedRangeProof from bytes array
		proof2 := new(BulletProof)
		proof2.SetBytes(bytes)

		// verify the proof
		res, err = proof2.Agg_Verify()
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)

		// verify the proof faster
		res, err = proof2.Agg_Verify_Fast()
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)
	}

}

func TestInnerProductProveVerify(t *testing.T) {
	for k := 0; k < 10; k++ {
		numValue := rand.Intn(maxOutputNumber)
		numValuePad := pad(numValue)
		aggParam := new(bulletproofParams)
		aggParam.g = AggParam.g[0 : numValuePad*maxExp]
		aggParam.h = AggParam.h[0 : numValuePad*maxExp]
		aggParam.u = AggParam.u
		aggParam.cs = AggParam.cs

		wit := new(InnerProductWitness)
		n := maxExp * numValuePad
		wit.a = make([]*crypto.Scalar, n)
		wit.b = make([]*crypto.Scalar, n)

		for i := range wit.a {
			//wit.a[i] = crypto.RandomScalar()
			//wit.b[i] = crypto.RandomScalar()
			wit.a[i] = new(crypto.Scalar).FromUint64(uint64(rand.Intn(100000)))
			wit.b[i] = new(crypto.Scalar).FromUint64(uint64(rand.Intn(100000)))
		}

		c, err := innerProduct(wit.a, wit.b)

		if err != nil {
			fmt.Printf("Err: %v\n", err)
		}
		wit.p = new(crypto.Point).ScalarMult(aggParam.u, c)

		for i := range wit.a {
			wit.p.Add(wit.p, new(crypto.Point).ScalarMult(aggParam.g[i], wit.a[i]))
			wit.p.Add(wit.p, new(crypto.Point).ScalarMult(aggParam.h[i], wit.b[i]))
		}

		proof, err := wit.Prove(aggParam)
		if err != nil {
			fmt.Printf("Err: %v\n", err)
			return
		}
		res2 := proof.Verify(aggParam)
		assert.Equal(t, true, res2)
		res2prime := proof.Verify_Fast(aggParam)
		assert.Equal(t, true, res2prime)

		bytes := proof.Bytes()
		proof2 := new(InnerProductProof)
		proof2.SetBytes(bytes)
		res3 := proof2.Verify(aggParam)
		assert.Equal(t, true, res3)
		res3prime := proof2.Verify(aggParam)
		assert.Equal(t, true, res3prime)
	}
}

func benchmarkAggRangeProof_Proof(numberofOutput int, b *testing.B) {
	wit := new(BulletWitness)
	values := make([]uint64, numberofOutput)
	rands := make([]*crypto.Scalar, numberofOutput)

	for i := range values {
		values[i] = uint64(rand.Uint64())
		rands[i] = crypto.RandomScalar()
	}
	wit.Set(values, rands)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		wit.Agg_Prove()
	}
}

func benchmarkAggRangeProof_Verify(numberofOutput int, b *testing.B) {
	wit := new(BulletWitness)
	values := make([]uint64, numberofOutput)
	rands := make([]*crypto.Scalar, numberofOutput)

	for i := range values {
		values[i] = uint64(common.RandInt64())
		rands[i] = crypto.RandomScalar()
	}
	wit.Set(values, rands)
	proof, _ := wit.Agg_Prove()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		proof.Agg_Verify()
	}
}

func benchmarkAggRangeProof_VerifyFast(numberofOutput int, b *testing.B) {
	wit := new(BulletWitness)
	values := make([]uint64, numberofOutput)
	rands := make([]*crypto.Scalar, numberofOutput)

	for i := range values {
		values[i] = uint64(common.RandInt64())
		rands[i] = crypto.RandomScalar()
	}
	wit.Set(values, rands)
	proof, _ := wit.Agg_Prove()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		proof.Agg_Verify_Fast()
	}
}

func BenchmarkAggregatedRangeWitness_Prove1(b *testing.B) { benchmarkAggRangeProof_Proof(1, b) }
func BenchmarkAggregatedRangeProof_Verify1(b *testing.B)  { benchmarkAggRangeProof_Verify(1, b) }
func BenchmarkAggregatedRangeProof_VerifyFast1(b *testing.B) {
	benchmarkAggRangeProof_VerifyFast(1, b)
}

func BenchmarkAggregatedRangeWitness_Prove2(b *testing.B) { benchmarkAggRangeProof_Proof(2, b) }
func BenchmarkAggregatedRangeProof_Verify2(b *testing.B)  { benchmarkAggRangeProof_Verify(2, b) }
func BenchmarkAggregatedRangeProof_VerifyFast2(b *testing.B) {
	benchmarkAggRangeProof_VerifyFast(2, b)
}

func BenchmarkAggregatedRangeWitness_Prove4(b *testing.B) { benchmarkAggRangeProof_Proof(4, b) }
func BenchmarkAggregatedRangeProof_Verify4(b *testing.B)  { benchmarkAggRangeProof_Verify(4, b) }
func BenchmarkAggregatedRangeProof_VerifyFast4(b *testing.B) {
	benchmarkAggRangeProof_VerifyFast(4, b)
}

func BenchmarkAggregatedRangeWitness_Prove8(b *testing.B) { benchmarkAggRangeProof_Proof(8, b) }
func BenchmarkAggregatedRangeProof_Verify8(b *testing.B)  { benchmarkAggRangeProof_Verify(8, b) }
func BenchmarkAggregatedRangeProof_VerifyFast8(b *testing.B) {
	benchmarkAggRangeProof_VerifyFast(8, b)
}

func BenchmarkAggregatedRangeWitness_Prove16(b *testing.B) { benchmarkAggRangeProof_Proof(16, b) }
func BenchmarkAggregatedRangeProof_Verify16(b *testing.B)  { benchmarkAggRangeProof_Verify(16, b) }
func BenchmarkAggregatedRangeProof_VerifyFast16(b *testing.B) {
	benchmarkAggRangeProof_VerifyFast(16, b)
}
