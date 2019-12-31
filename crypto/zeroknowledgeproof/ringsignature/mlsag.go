package ringsignature

import (
	"errors"
	"fmt"
	"github.com/incognitochain/incognito-chain-privacy/crypto"
	"time"
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
	hashPoint := crypto.HashToPoint(public.ToBytesS())
	res := new(crypto.Point).ScalarMult(hashPoint, private)
	return res
}

func (wit Mlsag_Witness) Mlsag_Prove() (*Mlsag_Proof, error) {
	startProve := time.Now()
	n := RingSize            // number of columns
	m := len(wit.privateKey) // number of rows
	index := wit.index

	// validate witness
	if len(wit.privateKey) < 1 {
		return nil, errors.New("Mlsag_Prove length of private list must be greater than 0")
	}
	if index >= n {
		return nil, errors.New("Mlsag_Prove Index out of range")
	}
	if len(wit.publicKey) != n {
		return nil, errors.New("Mlsag_Prove rows of public key list must be equal RingSize")
	}
	for i := 0; i < n; i++ {
		if len(wit.publicKey[i]) != m {
			return nil, errors.New("Mlsag_Prove cols of public key list must be equal length of private key list")
		}
	}

	// Step 1: Calculate key images:
	keyImage := make([]*crypto.Point, m)
	for j := 0; j < m; j++ {
		keyImage[j] = key_image(wit.privateKey[j], wit.publicKey[index][j])
	}

	// Step 2: Generate random numbers alpha
	r := make([][]*crypto.Scalar, n)
	for i := 0; i < n; i++ {
		r[i] = make([]*crypto.Scalar, m)
		for j := 0; j < m; j++ {
			r[i][j] = crypto.RandomScalar()
		}
	}

	// Step 3: Compute c array
	c := make([]*crypto.Scalar, n)

	// compute c[index] first
	dataTmp := []byte{}
	dataTmp = append(dataTmp, wit.message.ToBytesS()...)
	for j := 0; j < m; j++ {
		alpha := r[index][j]
		gTmp := new(crypto.Point).ScalarMultBase(alpha)
		hTmp := new(crypto.Point).ScalarMult(crypto.HashToPoint(wit.publicKey[index][j].ToBytesS()), alpha)
		dataTmp = append(dataTmp, gTmp.ToBytesS()...)
		dataTmp = append(dataTmp, hTmp.ToBytesS()...)
	}
	c[index+1] = crypto.HashToScalar(dataTmp)

	// compute c[i], i != index
	for i := index + 1; ; i++ {
		i = i % n
		dataTmp := []byte{}
		dataTmp = append(dataTmp, wit.message.ToBytesS()...)

		for j := 0; j < m; j++ {
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
		tmpIndex := (i + 1) % n
		c[tmpIndex] = crypto.HashToScalar(dataTmp)

		if tmpIndex == index {
			break
		}
	}

	// Step 5: define r[index][j]
	for j := 0; j < m; j++ {
		tmp := new(crypto.Scalar).Mul(c[index], wit.privateKey[j])
		r[index][j] = r[index][j].Sub(r[index][j], tmp)
	}

	proof := &Mlsag_Proof{
		c0: c[0],
		r:  r,

		publicKey: wit.publicKey,
		keyImage:  keyImage,
		message:   wit.message,
	}

	proveTime := time.Since(startProve)
	fmt.Printf("proveTime: %v - len private key %v: ", proveTime, len(wit.privateKey))

	return proof, nil
}

func (proof Mlsag_Proof) Mlsag_Verify() bool {
	startVerify := time.Now()
	n := RingSize            // number of columns
	m := len(proof.keyImage) // number of rows

	// Step 1: Check keyImage valid or not
	//for i:=0; i<m; i++ {
	//	proof.keyImage[i]
	//}

	c := make([]*crypto.Scalar, n)
	c[0] = new(crypto.Scalar).Set(proof.c0)
	for i := 0; i < n; i++ {
		dataTmp := []byte{}
		dataTmp = append(dataTmp, proof.message.ToBytesS()...)

		for j := 0; j < m; j++ {
			rand := proof.r[i][j]

			// gTmp = G^rand * K[i][j]^c[i]
			gTmp := new(crypto.Point).ScalarMultBase(rand)
			gTmp.Add(gTmp, new(crypto.Point).ScalarMult(proof.publicKey[i][j], c[i]))

			// hTmp = Hp(K[i][j])^rand * keyImage[j]^c[i]
			hTmp := new(crypto.Point).ScalarMult(crypto.HashToPoint(proof.publicKey[i][j].ToBytesS()), rand)
			hTmp.Add(hTmp, new(crypto.Point).ScalarMult(proof.keyImage[j], c[i]))

			dataTmp = append(dataTmp, gTmp.ToBytesS()...)
			dataTmp = append(dataTmp, hTmp.ToBytesS()...)
		}

		c[(i+1)%n] = crypto.HashToScalar(dataTmp)
	}

	res := crypto.IsScalarEqual(c[0], proof.c0)

	verifyTime := time.Since(startVerify)
	fmt.Printf("verifyTime: %v - len private key %v: ", verifyTime, len(proof.publicKey))
	return res
}

func (wit Mlsag_Witness) Mlsag_Prove2() (*Mlsag_Proof, error) {
	//startProve := time.Now()
	n := RingSize            // number of rows, Ring Size
	m := len(wit.privateKey) // number of columns, number of private keys
	index := wit.index       // prover knows private keys of column at index
	dsCols := wit.dsCols
	messageBytes := wit.message.ToBytesS()

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
	//aG := make([]*crypto.Point, m)
	//aHP := make([]*crypto.Point, dsCols)
	aG := new(crypto.Point)
	aHP := new(crypto.Point)

	//toHash := make([]*crypto.Point, 1+3*dsCols+2*(m-dsCols))
	//toHash[0] = wit.message
	toHashBytes := make([]byte, 0)
	toHashBytes = messageBytes

	for j := 0; j < dsCols; j++ {
		alpha[j] = crypto.RandomScalar()
		aG = new(crypto.Point).ScalarMultBase(alpha[j])

		Hi = crypto.HashToPoint(wit.publicKey[index][j].ToBytesS())
		aHP = new(crypto.Point).ScalarMult(Hi, alpha[j])

		//toHash[3*j+1] = wit.publicKey[index][j]
		//toHash[3*j+2] = aG[j]
		//toHash[3*j+3] = aHP[j]

		//toHashBytes = append(toHashBytes, wit.publicKey[index][j].ToBytesS()...)
		//toHashBytes = append(toHashBytes, aG[j].ToBytesS()...)
		//toHashBytes = append(toHashBytes, aHP[j].ToBytesS()...)
		toHashBytes = AppendPointsToBytesArray(toHashBytes, []*crypto.Point{wit.publicKey[index][j], aG, aHP})

		// Calculate key images for private key j
		keyImage[j] = key_image(wit.privateKey[j], Hi)
	}

	//ndsCols := 3 * dsCols
	for j, j2 := dsCols, 0; j < m; j, j2 = j+1,j2+1 {
		alpha[j] = crypto.RandomScalar()
		aG = new(crypto.Point).ScalarMultBase(alpha[j])

		//toHash[ndsCols+2*j2+1] = wit.publicKey[index][j]
		//toHash[ndsCols+2*j2+2] = aG[j]

		//toHashBytes = append(toHashBytes, wit.publicKey[index][j].ToBytesS()...)
		//toHashBytes = append(toHashBytes, aG[j].ToBytesS()...)

		toHashBytes = AppendPointsToBytesArray(toHashBytes, []*crypto.Point{wit.publicKey[index][j], aG})
	}

	//for _, item := range toHash {
	//	toHashBytes = append(toHashBytes, item.ToBytesS()...)
	//}

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
			Hi = crypto.HashToPoint(wit.publicKey[i][j].ToBytesS())

			R = new(crypto.Point).AddPedersen(r[i][j], Hi, c_old, keyImage[j])
			//toHash[3*j+1] = wit.publicKey[i][j]
			//toHash[3*j+2] = L
			//toHash[3*j+3] = R

			//toHashBytes = append(toHashBytes, wit.publicKey[i][j].ToBytesS()...)
			//toHashBytes = append(toHashBytes, L.ToBytesS()...)
			//toHashBytes = append(toHashBytes, R.ToBytesS()...)

			toHashBytes = AppendPointsToBytesArray(toHashBytes, []*crypto.Point{wit.publicKey[index][j], L, R})
		}

		for j, j2 := dsCols, 0; j < m; j, j2 = j+1,j2+1 {
			L = new(crypto.Point).AddPedersen(r[i][j], crypto.G, c_old, wit.publicKey[i][j])
			//toHash[ndsCols+2*j2+1] = wit.publicKey[i][j]
			//toHash[ndsCols+2*j2+2] = L

			//toHashBytes = append(toHashBytes, wit.publicKey[i][j].ToBytesS()...)
			//toHashBytes = append(toHashBytes, L.ToBytesS()...)
			toHashBytes = AppendPointsToBytesArray(toHashBytes, []*crypto.Point{wit.publicKey[index][j], L})
		}

		//toHashBytes = []byte{}
		//for _, item := range toHash {
		//	toHashBytes = append(toHashBytes, item.ToBytesS()...)
		//}

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
		dsCols: dsCols,
	}

	//fmt.Printf("Prove c: %v\n", c0)
	//fmt.Printf("Prove proof.c0: %v\n", proof.c0)

	//proveTime := time.Since(startProve)
	//fmt.Printf("proveTime: %v - len private key %v: \n", proveTime, len(wit.privateKey))

	return proof, nil
}

func (proof Mlsag_Proof) Mlsag_Verify2() (bool, error) {
	//startVerify := time.Now()
	n := RingSize                // number of rows
	m := len(proof.publicKey[0]) // number of columns
	dsCols := proof.dsCols
	messageBytes := proof.message.ToBytesS()

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

	//ndsCols := 3 * dsCols
	//toHash := make([]*crypto.Point, 1+3*dsCols+2*(m-dsCols))
	//toHash[0] = proof.message
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
			Hi = crypto.HashToPoint(proof.publicKey[i][j].ToBytesS())

			R = new(crypto.Point).AddPedersen(proof.r[i][j], Hi, c_old, proof.keyImage[j])
			//toHash[3*j+1] = proof.publicKey[i][j]
			//toHash[3*j+2] = L
			//toHash[3*j+3] = R

			toHashBytes = AppendPointsToBytesArray(toHashBytes, []*crypto.Point{proof.publicKey[i][j], L, R})
		}

		for j, j2 := dsCols, 0; j < m; j, j2 = j+1,j2+1 {
			L = new(crypto.Point).AddPedersen(proof.r[i][j], crypto.G, c_old, proof.publicKey[i][j])
			//toHash[ndsCols+2*j2+1] = proof.publicKey[i][j]
			//toHash[ndsCols+2*j2+2] = L

			toHashBytes = AppendPointsToBytesArray(toHashBytes, []*crypto.Point{proof.publicKey[i][j], L})
		}

		//toHashBytes = []byte{}
		//for _, item := range toHash {
		//	toHashBytes = append(toHashBytes, item.ToBytesS()...)
		//}

		c = crypto.HashToScalar(toHashBytes)
		c_old.Set(c)
	}

	//fmt.Printf("Verify c: %v\n", c)
	//fmt.Printf("Verify proof.c0: %v\n", proof.c0)
	res := crypto.IsScalarEqual(c, proof.c0)

	//verifyTime := time.Since(startVerify)
	//fmt.Printf("verifyTime: %v - len private key %v: \n", verifyTime, m)
	return res, nil
}


func AppendPointsToBytesArray(bytes []byte, points []*crypto.Point) []byte{
	res := bytes
	for i:=0; i<len(points); i++{
		res = append(res, points[i].ToBytesS()...)
	}

	return res
}