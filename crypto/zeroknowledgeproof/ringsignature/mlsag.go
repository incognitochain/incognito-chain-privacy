package ringsignature

import (
	"fmt"
	"github.com/incognitochain/incognito-chain-privacy/crypto"
	"time"
)

// Multilayer Linkable Spontaneous Anonymous Group (mlsag)
// PAPER: https://web.getmonero.org/library/Zero-to-Monero-1-0-0.pdf (Chapter 3.3)

const RingSize = 8

type Mlsag_Witness struct {
	privateKey []*crypto.Scalar
	index int

	publicKey [][]*crypto.Point
	message []byte
}

type Mlsag_Proof struct {
	c0 *crypto.Scalar
	r  [][]*crypto.Scalar
	k  []*crypto.Point

	publicKey [][]*crypto.Point
	message []byte
}

func key_image(private *crypto.Scalar, public *crypto.Point) *crypto.Point {
	hashPoint := crypto.HashToPoint(public.ToBytesS())
	res := new(crypto.Point).ScalarMult(hashPoint, private)
	return res
}


func (wit Mlsag_Witness) Mlsag_Prove() (*Mlsag_Proof, error){
	startProve:= time.Now()
	n := RingSize			// number of columns
	m := len(wit.privateKey) // number of lines
	index := wit.index

	// Step 1: Calculate key images:
	keyImage := make([]*crypto.Point, m)
	for j:=0; j<m; j++{
		keyImage[j] = key_image(wit.privateKey[j], wit.publicKey[index][j])
	}

	// Step 2: Generate random numbers alpha
	r := make([][]*crypto.Scalar, n)
	for i :=0; i<n; i++{
		r[i] = make([]*crypto.Scalar, m)
		for j :=0; j<m; j++{
			r[i][j]= crypto.RandomScalar()
		}
	}

	// Step 3: Compute c array
	c := make([]*crypto.Scalar, n)

	// compute c[index] first
	dataTmp := []byte{}
	dataTmp = append(dataTmp, wit.message...)
	for j:=0; j<m; j++ {
		alpha := r[index][j]
		gTmp := new(crypto.Point).ScalarMultBase(alpha)
		hTmp := new(crypto.Point).ScalarMult(crypto.HashToPoint(wit.publicKey[index][j].ToBytesS()), alpha)
		dataTmp = append(dataTmp, gTmp.ToBytesS()...)
		dataTmp = append(dataTmp, hTmp.ToBytesS()...)
	}
	c[index+1] = crypto.HashToScalar(dataTmp)

	// compute c[i], i != index
	for i := index+1; ; i++ {
		i = i % n
		dataTmp := []byte{}
		dataTmp = append(dataTmp, wit.message...)

		for j:=0; j<m; j++ {
			rand := r[i][j]

			// gTmp = G^rand * K[i][j]^c[i]
			gTmp := new(crypto.Point).ScalarMultBase(rand)
			gTmp.Add(gTmp, new(crypto.Point).ScalarMult(wit.publicKey[i][j], c[i]))

			// hTmp = Hp(K[i][j])^rand * keyImage[j]^c[i]
			hTmp := new(crypto.Point).ScalarMult(crypto.HashToPoint(wit.publicKey[i][j].ToBytesS()), rand)
			hTmp.Add(hTmp, new(crypto.Point).ScalarMult(keyImage[j], c[i]))

			dataTmp = append(dataTmp, gTmp.ToBytesS()...)
			dataTmp = append(dataTmp, hTmp.ToBytesS()...)
		}
		tmpIndex := (i+1) % n
		c[tmpIndex] = crypto.HashToScalar(dataTmp)

		if tmpIndex == index {
			break
		}
	}

	// Step 5: define r[index][j]
	for j := 0; j<m; j++ {
		tmp := new(crypto.Scalar).Mul(c[index], wit.privateKey[j])
		r[index][j] = r[index][j].Sub(r[index][j], tmp)
	}

	fmt.Printf("Prove c: %v\n", c)

	proof := &Mlsag_Proof{
		c0: c[0],
		r:  r,

		publicKey: wit.publicKey,
		k: keyImage,
		message: wit.message,
	}

	proveTime := time.Since(startProve)
	fmt.Printf("proveTime: %v - len private key %v: ", proveTime, len(wit.privateKey))

	return proof, nil
}

func (proof Mlsag_Proof) Mlsag_Verify() bool{
	n := RingSize			// number of columns
	m := len(proof.k) // number of lines

	// Step 1: Check k valid or not
	//for i:=0; i<m; i++ {
	//	proof.k[i]
	//}

	c := make([]*crypto.Scalar, n)
	c[0] = new(crypto.Scalar).Set(proof.c0)
	for i:=0; i<n; i++{
		dataTmp := []byte{}
		dataTmp = append(dataTmp, proof.message...)

		for j:=0; j<m; j++ {
			rand := proof.r[i][j]

			// gTmp = G^rand * K[i][j]^c[i]
			gTmp := new(crypto.Point).ScalarMultBase(rand)
			gTmp.Add(gTmp, new(crypto.Point).ScalarMult(proof.publicKey[i][j], c[i]))

			// hTmp = Hp(K[i][j])^rand * keyImage[j]^c[i]
			hTmp := new(crypto.Point).ScalarMult(crypto.HashToPoint(proof.publicKey[i][j].ToBytesS()), rand)
			hTmp.Add(hTmp, new(crypto.Point).ScalarMult(proof.k[j], c[i]))

			dataTmp = append(dataTmp, gTmp.ToBytesS()...)
			dataTmp = append(dataTmp, hTmp.ToBytesS()...)
		}

		c[(i+1)%n] = crypto.HashToScalar(dataTmp)
	}
	fmt.Printf("Verify c: %v\n", c)

	return crypto.IsScalarEqual(c[0], proof.c0)
}

