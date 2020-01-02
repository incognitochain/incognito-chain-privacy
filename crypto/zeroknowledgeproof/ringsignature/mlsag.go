package ringsignature

import (
	"errors"
	"fmt"
	"github.com/incognitochain/incognito-chain-privacy/crypto"
)

// Multilayer Linkable Spontaneous Anonymous Group (mlsag)
// PAPER: https://web.getmonero.org/library/Zero-to-Monero-1-0-0.pdf (Chapter 3.3)

const RingSize = 8

type Mlsag_Witness struct {
	privateKey []*crypto.Scalar
	index      int

	dsCols    int // number of cols that need to be checked double spending
	publicKey [][]*crypto.Point
	message   *crypto.Point
}

type Mlsag_Proof struct {
	c0       *crypto.Scalar
	r        [][]*crypto.Scalar
	keyImage []*crypto.Point

	dsCols    int // number of cols that need to be checked double spending
	publicKey [][]*crypto.Point
	message   *crypto.Point
}

func key_image(private *crypto.Scalar, public *crypto.Point) *crypto.Point {
	hashPoint := crypto.HashToPoint(public.ToBytes())
	res := new(crypto.Point).ScalarMult(hashPoint, private)
	return res
}

func (wit Mlsag_Witness) Mlsag_Prove() (*Mlsag_Proof, error) {
	//startProve := time.Now()
	n := RingSize            // number of rows, Ring Size
	m := len(wit.privateKey) // number of columns, number of private keys
	index := wit.index       // prover knows private keys of column at index
	dsCols := wit.dsCols
	messageBytes := wit.message.ToBytes()

	// validate witness
	if m < 2 {
		return nil, errors.New("Mlsag_Prove length of private list must be at least 2")
	}
	if index >= n {
		return nil, errors.New("Mlsag_Prove Index out of range")
	}
	if dsCols > m {
		return nil, errors.New("Mlsag_Prove dsCols must not be greater than length of private key list")
	}
	if len(wit.publicKey) != n {
		return nil, errors.New("Mlsag_Prove cols of public key matrix must be equal RingSize")
	}
	for i := 0; i < n; i++ {
		if len(wit.publicKey[i]) != m {
			return nil, errors.New("Mlsag_Prove rows of public key matrix must be equal length of private key list")
		}
	}

	// Step 1: Calculate key images for dsCols private keys
	Hi := new(crypto.Point)
	keyImage := make([]*crypto.Point, dsCols)
	alpha := make([]*crypto.Scalar, m)
	aG := new(crypto.Point)
	aHP := new(crypto.Point)

	toHashBytes := make([]byte, 0)
	toHashBytes = messageBytes

	for j := 0; j < dsCols; j++ {
		alpha[j] = crypto.RandomScalar()
		aG = new(crypto.Point).ScalarMultBase(alpha[j])

		Hi = crypto.HashToPoint(wit.publicKey[index][j].ToBytes())
		aHP = new(crypto.Point).ScalarMult(Hi, alpha[j])

		toHashBytes = crypto.AppendPointsToBytesArray(toHashBytes, []*crypto.Point{wit.publicKey[index][j], aG, aHP})

		// Calculate key images for private key j
		keyImage[j] = key_image(wit.privateKey[j], Hi)
	}

	for j, j2 := dsCols, 0; j < m; j, j2 = j+1, j2+1 {
		alpha[j] = crypto.RandomScalar()
		aG = new(crypto.Point).ScalarMultBase(alpha[j])

		toHashBytes = crypto.AppendPointsToBytesArray(toHashBytes, []*crypto.Point{wit.publicKey[index][j], aG})
	}

	c_old := crypto.HashToScalar(toHashBytes)
	c0 := new(crypto.Scalar)
	c := new(crypto.Scalar)
	L := new(crypto.Point)
	R := new(crypto.Point)
	r := make([][]*crypto.Scalar, n)
	for i := 0; i < n; i++ {
		r[i] = make([]*crypto.Scalar, m)
	}

	i := (index + 1) % n
	if i == 0 {
		c0 = c_old
	}

	for i != index {
		for j := 0; j < m; j++ {
			r[i][j] = crypto.RandomScalar()
		}

		toHashBytes = messageBytes

		for j := 0; j < dsCols; j++ {
			L = new(crypto.Point).AddPedersen(r[i][j], crypto.G, c_old, wit.publicKey[i][j])
			Hi = crypto.HashToPoint(wit.publicKey[i][j].ToBytes())
			R = new(crypto.Point).AddPedersen(r[i][j], Hi, c_old, keyImage[j])

			toHashBytes = crypto.AppendPointsToBytesArray(toHashBytes, []*crypto.Point{wit.publicKey[index][j], L, R})
		}

		for j, j2 := dsCols, 0; j < m; j, j2 = j+1, j2+1 {
			L = new(crypto.Point).AddPedersen(r[i][j], crypto.G, c_old, wit.publicKey[i][j])
			toHashBytes = crypto.AppendPointsToBytesArray(toHashBytes, []*crypto.Point{wit.publicKey[index][j], L})
		}

		c = crypto.HashToScalar(toHashBytes)
		c_old.Set(c)

		i = (i + 1) % n
		if i == 0 {
			c0 = c_old
		}
	}

	for j := 0; j < m; j++ {
		r[index][j] = new(crypto.Scalar).Sub(alpha[j], new(crypto.Scalar).Mul(c, wit.privateKey[j]))
	}

	proof := &Mlsag_Proof{
		c0: c0,
		r:  r,

		publicKey: wit.publicKey,
		keyImage:  keyImage,
		message:   wit.message,
		dsCols:    dsCols,
	}

	//proveTime := time.Since(startProve)
	//fmt.Printf("proveTime: %v - len private key %v: \n", proveTime, len(wit.privateKey))

	return proof, nil
}

func (proof Mlsag_Proof) Mlsag_Verify() (bool, error) {
	//startVerify := time.Now()
	n := RingSize                // number of rows
	m := len(proof.publicKey[0]) // number of columns
	dsCols := proof.dsCols
	messageBytes := proof.message.ToBytes()

	//validate proof
	if m < 2 {
		return false, errors.New("Mlsag_Verify length of private list must be at least 2")
	}
	if dsCols > m {
		return false, errors.New("Mlsag_Verify dsCols must not be greater than number of cols")
	}
	if dsCols != len(proof.keyImage) {
		return false, errors.New("Mlsag_Verify dsCols must be equal length of key image list")
	}
	if len(proof.publicKey) != n {
		return false, errors.New("Mlsag_Verify cols of public key matrix must be equal RingSize")
	}
	for i := 1; i < n; i++ {
		if len(proof.publicKey[i]) != m {
			return false, errors.New("Mlsag_Verify rows of public key matrix must be equal number of cols")
		}
	}
	if len(proof.r) != n {
		return false, errors.New("Mlsag_Verify cols of r matrix must be equal RingSize")
	}
	for i := 0; i < n; i++ {
		if len(proof.r[i]) != m {
			return false, errors.New("Mlsag_Verify rows of r matrix must be equal number of cols")
		}
	}

	// Step 1: Check keyImage valid or not
	for j := 0; j < dsCols; j++ {
		if !proof.keyImage[j].PointValid() {
			return false, fmt.Errorf("Mlsag_Verify key image is invalid %v\n", proof.keyImage[j])
		}
	}

	if !proof.c0.ScalarValid() {
		return false, fmt.Errorf("Mlsag_Verify c0 is invalid %v\n", proof.c0)
	}

	toHashBytes := make([]byte, 0)

	c_old := proof.c0
	c := new(crypto.Scalar)
	L := new(crypto.Point)
	R := new(crypto.Point)
	Hi := new(crypto.Point)
	for i := 0; i < n; i++ {
		toHashBytes = messageBytes

		for j := 0; j < dsCols; j++ {
			L = new(crypto.Point).AddPedersen(proof.r[i][j], crypto.G, c_old, proof.publicKey[i][j])
			Hi = crypto.HashToPoint(proof.publicKey[i][j].ToBytes())
			R = new(crypto.Point).AddPedersen(proof.r[i][j], Hi, c_old, proof.keyImage[j])

			toHashBytes = crypto.AppendPointsToBytesArray(toHashBytes, []*crypto.Point{proof.publicKey[i][j], L, R})
		}

		for j, j2 := dsCols, 0; j < m; j, j2 = j+1, j2+1 {
			L = new(crypto.Point).AddPedersen(proof.r[i][j], crypto.G, c_old, proof.publicKey[i][j])

			toHashBytes = crypto.AppendPointsToBytesArray(toHashBytes, []*crypto.Point{proof.publicKey[i][j], L})
		}

		c = crypto.HashToScalar(toHashBytes)
		c_old.Set(c)
	}

	res := crypto.CompareScalar(c, proof.c0) == 0

	//verifyTime := time.Since(startVerify)
	//fmt.Printf("verifyTime: %v - len private key %v: \n", verifyTime, m)
	return res, nil
}
