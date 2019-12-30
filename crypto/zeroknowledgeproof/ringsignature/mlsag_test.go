package ringsignature

import (
	"github.com/incognitochain/incognito-chain-privacy/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMlsag(t *testing.T){
	wit := new(Mlsag_Witness)
	m := 255
	n := RingSize
	wit.message = []byte{1,2,3}
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
