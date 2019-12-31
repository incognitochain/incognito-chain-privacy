package ringsignature

import (
	"github.com/incognitochain/incognito-chain-privacy/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMlsag(t *testing.T){
	wit := new(Mlsag_Witness)
	m := 2
	n := RingSize
	wit.message = crypto.RandomPoint()
	wit.index = 2

	wit.publicKey = make([][]*crypto.Point, n)
	for i:=0; i<n; i++{
		wit.publicKey[i] = make([]*crypto.Point, m)
		for j:=0; j<m; j++ {
			wit.publicKey[i][j] = crypto.RandomPoint()
		}
	}

	wit.privateKey = make([]*crypto.Scalar, m)
	for j :=0; j<m; j++{
		wit.privateKey[j] = crypto.RandomScalar()
		wit.publicKey[wit.index][j] = new(crypto.Point).ScalarMultBase(wit.privateKey[j])
	}

	proof, err := wit.Mlsag_Prove()
	assert.Equal(t, nil, err)

	resVerify := proof.Mlsag_Verify()
	assert.Equal(t, true, resVerify)
}

func TestMlsag2(t *testing.T){
	wit := new(Mlsag_Witness)
	m := 2
	n := RingSize
	wit.message = crypto.RandomPoint()
	wit.index = 2
	wit.dsCols = 1

	wit.publicKey = make([][]*crypto.Point, n)
	for i:=0; i<n; i++{
		wit.publicKey[i] = make([]*crypto.Point, m)
		for j:=0; j<m; j++ {
			wit.publicKey[i][j] = crypto.RandomPoint()
		}
	}

	wit.privateKey = make([]*crypto.Scalar, m)
	for j :=0; j<m; j++{
		wit.privateKey[j] = crypto.RandomScalar()
		wit.publicKey[wit.index][j] = new(crypto.Point).ScalarMultBase(wit.privateKey[j])
	}

	proof, err := wit.Mlsag_Prove2()
	assert.Equal(t, nil, err)

	resVerify, err := proof.Mlsag_Verify2()
	assert.Equal(t, nil, err)
	assert.Equal(t, true, resVerify)
}

func benchmarkMlsag_Prove(b *testing.B, mParam int){
	wit := new(Mlsag_Witness)
	m := mParam
	n := RingSize
	wit.message = crypto.RandomPoint()
	wit.index = 2
	wit.dsCols = 1

	wit.publicKey = make([][]*crypto.Point, n)
	for i:=0; i<n; i++{
		wit.publicKey[i] = make([]*crypto.Point, m)
		for j:=0; j<m; j++ {
			wit.publicKey[i][j] = crypto.RandomPoint()
		}
	}

	wit.privateKey = make([]*crypto.Scalar, m)
	for j :=0; j<m; j++{
		wit.privateKey[j] = crypto.RandomScalar()
		wit.publicKey[wit.index][j] = new(crypto.Point).ScalarMultBase(wit.privateKey[j])
	}

	for i:=0; i<b.N; i++ {
		wit.Mlsag_Prove2()
	}
}

func benchmarkMlsag_Verify(b *testing.B, mParam int){
	wit := new(Mlsag_Witness)
	m := mParam
	n := RingSize
	wit.message = crypto.RandomPoint()
	wit.index = 2
	wit.dsCols = 1

	wit.publicKey = make([][]*crypto.Point, n)
	for i:=0; i<n; i++{
		wit.publicKey[i] = make([]*crypto.Point, m)
		for j:=0; j<m; j++ {
			wit.publicKey[i][j] = crypto.RandomPoint()
		}
	}

	wit.privateKey = make([]*crypto.Scalar, m)
	for j :=0; j<m; j++{
		wit.privateKey[j] = crypto.RandomScalar()
		wit.publicKey[wit.index][j] = new(crypto.Point).ScalarMultBase(wit.privateKey[j])
	}
	proof, _ := wit.Mlsag_Prove2()

	for i:=0; i<b.N; i++ {
		proof.Mlsag_Verify2()
	}
}

func BenchmarkMlsag_Prove(b *testing.B){
	benchmarkMlsag_Prove(b, 2)
}

func BenchmarkMlsag_Verify(b *testing.B){
	benchmarkMlsag_Verify(b, 2)
}
