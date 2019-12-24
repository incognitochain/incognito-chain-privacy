package curve25519

import (
	C25519 "github.com/deroproject/derosuite/crypto"
	"reflect"
	"unsafe"
)

func signedRadix16(k *C25519.Key) [64]int8 {
	if k[31] > 127 {
		panic("scalar has high bit set illegally")
	}

	var digits [64]int8

	// Compute unsigned radix-16 digits:
	for i := 0; i < 32; i++ {
		digits[2*i] = int8(k[i] & 15)
		digits[2*i+1] = int8((k[i] >> 4) & 15)
	}

	// Recenter coefficients:
	for i := 0; i < 63; i++ {
		carry := (digits[i] + 8) >> 4
		digits[i] -= carry << 4
		digits[i+1] += carry
	}

	return digits
}

// equal returns 1 if b == c and 0 otherwise, assuming that b and c are
// non-negative.
func equal(b, c int32) int32 {
	x := uint32(b ^ c)
	x--
	return int32(x >> 31)
}

// negative returns 1 if b < 0 and 0 otherwise.
func negative(b int32) int32 {
	return (b >> 31) & 1
}

//func (ge * C25519.CachedGroupElement)  getYPlusX() {
//
//}

func MultiScalarMultKeyCached(AiLs [][8]C25519.CachedGroupElement, scalars []*C25519.Key, ) (result *C25519.Key) {
	r := new(C25519.ProjectiveGroupElement)

	digitsLs := make([][64]int8, len(scalars))
	for i := range digitsLs {
		digitsLs[i] = signedRadix16(scalars[i])
	}

	t := new(C25519.CompletedGroupElement)
	u := new(C25519.ExtendedGroupElement)

	r.Zero()
	cachedBase := new(C25519.ExtendedGroupElement)
	cur := new(C25519.CachedGroupElement)
	minusCur := new(C25519.CachedGroupElement)

	curReflect := reflect.ValueOf(cur).Elem()
	curYPlusX := curReflect.FieldByName("yPlusX")  // yPlusX
	curYMinusX := curReflect.FieldByName("yMinusX") // yMinusX
	// curYPlusX, curYMinusX can't be read or set.
	curYPlusX = reflect.NewAt(curYPlusX.Type(), unsafe.Pointer(curYPlusX.UnsafeAddr())).Elem()
	curYMinusX = reflect.NewAt(curYMinusX.Type(), unsafe.Pointer(curYMinusX.UnsafeAddr())).Elem()
	// Now curYPlusX, curYMinusX can be read and set.

	minusCurReflect := reflect.ValueOf(minusCur).Elem()
	minusCurYPlusX := minusCurReflect.FieldByName("yPlusX")  // yPlusX
	minusCurYMinusX := minusCurReflect.FieldByName("yMinusX") // yMinusX
	// minusCurYPlusX, minusCurYMinusX can't be read or set.
	minusCurYPlusX = reflect.NewAt(minusCurYPlusX.Type(), unsafe.Pointer(minusCurYPlusX.UnsafeAddr())).Elem()
	minusCurYMinusX = reflect.NewAt(minusCurYMinusX.Type(), unsafe.Pointer(minusCurYMinusX.UnsafeAddr())).Elem()
	// Now minusCurYPlusX, minusCurYMinusX can be read and set.

	for i := 63; i >= 0; i-- {
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToExtended(u)

		cachedBase.Zero()
		tmpt := new(C25519.CompletedGroupElement)
		for j := 0; j < len(scalars); j++ {
			cur.Zero()
			b := digitsLs[j][i]
			bNegative := int8(negative(int32(b)))
			bAbs := b - (((-bNegative) & b) << 1)

			for k := int32(0); k < 8; k++ {
				if equal(int32(bAbs), k+1) == 1 { // optimisation
					C25519.CachedGroupElementCMove(cur, &AiLs[j][k], equal(int32(bAbs), k+1))
				}
			}

			//todo:
			minusCurYPlusX.Set(curYMinusX)
			minusCurYMinusX.Set(curYPlusX)

			//C25519.FeCopy(&minusCur.yPlusX, &cur.yMinusX)
			//C25519.FeCopy(&minusCur.yMinusX, &cur.yPlusX)
			C25519.FeCopy(&minusCur.Z, &cur.Z)
			C25519.FeNeg(&minusCur.T2d, &cur.T2d)
			C25519.CachedGroupElementCMove(cur, minusCur, int32(bNegative))

			C25519.GeAdd(tmpt, cachedBase, cur)
			tmpt.ToExtended(cachedBase)
		}
		tmpv := new(C25519.CachedGroupElement)
		cachedBase.ToCached(tmpv)
		C25519.GeAdd(t, u, tmpv)
		t.ToProjective(r)
	}
	result = new(C25519.Key)
	r.ToBytes(result)
	return result
}

func MultiScalarMultKey(points []*C25519.Key, scalars []*C25519.Key) (result *C25519.Key) {
	r := new(C25519.ProjectiveGroupElement)

	pointLs := make([]C25519.ExtendedGroupElement, len(points))

	digitsLs := make([][64]int8, len(scalars))
	for i := range digitsLs {
		digitsLs[i] = signedRadix16(scalars[i])
	}

	AiLs := make([][8]C25519.CachedGroupElement, len(scalars))
	for i := 0; i < len(scalars); i++ {
		// A,2A,3A,4A,5A,6A,7A,8A
		t := new(C25519.CompletedGroupElement)
		u := new(C25519.ExtendedGroupElement)
		pointLs[i].FromBytes(points[i])
		pointLs[i].ToCached(&AiLs[i][0])
		for j := 0; j < 7; j++ {
			C25519.GeAdd(t, &pointLs[i], &AiLs[i][j])
			t.ToExtended(u)
			u.ToCached(&AiLs[i][j+1])
		}
	}

	t := new(C25519.CompletedGroupElement)
	u := new(C25519.ExtendedGroupElement)

	r.Zero()
	cachedBase := new(C25519.ExtendedGroupElement)
	cur := new(C25519.CachedGroupElement)
	minusCur := new(C25519.CachedGroupElement)

	curReflect := reflect.ValueOf(cur).Elem()
	curYPlusX := curReflect.FieldByName("yPlusX")  // yPlusX
	curYMinusX := curReflect.FieldByName("yMinusX") // yMinusX
	// curYPlusX, curYMinusX can't be read or set.
	curYPlusX = reflect.NewAt(curYPlusX.Type(), unsafe.Pointer(curYPlusX.UnsafeAddr())).Elem()
	curYMinusX = reflect.NewAt(curYMinusX.Type(), unsafe.Pointer(curYMinusX.UnsafeAddr())).Elem()
	// Now curYPlusX, curYMinusX can be read and set.

	minusCurReflect := reflect.ValueOf(minusCur).Elem()
	minusCurYPlusX := minusCurReflect.FieldByName("yPlusX")  // yPlusX
	minusCurYMinusX := minusCurReflect.FieldByName("yMinusX") // yMinusX
	// minusCurYPlusX, minusCurYMinusX can't be read or set.
	minusCurYPlusX = reflect.NewAt(minusCurYPlusX.Type(), unsafe.Pointer(minusCurYPlusX.UnsafeAddr())).Elem()
	minusCurYMinusX = reflect.NewAt(minusCurYMinusX.Type(), unsafe.Pointer(minusCurYMinusX.UnsafeAddr())).Elem()
	// Now minusCurYPlusX, minusCurYMinusX can be read and set.

	for i := 63; i >= 0; i-- {
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToExtended(u)

		cachedBase.Zero()
		tmpt := new(C25519.CompletedGroupElement)
		for j := 0; j < len(scalars); j++ {
			cur.Zero()
			b := digitsLs[j][i]
			bNegative := int8(negative(int32(b)))
			bAbs := b - (((-bNegative) & b) << 1)

			for k := int32(0); k < 8; k++ {
				if equal(int32(bAbs), k+1) == 1 { // optimisation
					C25519.CachedGroupElementCMove(cur, &AiLs[j][k], equal(int32(bAbs), k+1))
				}
			}

			minusCurYPlusX.Set(curYMinusX)
			minusCurYMinusX.Set(curYPlusX)

			//C25519.FeCopy(&minusCur.yPlusX, &cur.yMinusX)
			//C25519.FeCopy(&minusCur.yMinusX, &cur.yPlusX)

			C25519.FeCopy(&minusCur.Z, &cur.Z)
			C25519.FeNeg(&minusCur.T2d, &cur.T2d)
			C25519.CachedGroupElementCMove(cur, minusCur, int32(bNegative))

			C25519.GeAdd(tmpt, cachedBase, cur)
			tmpt.ToExtended(cachedBase)
		}
		tmpv := new(C25519.CachedGroupElement)
		cachedBase.ToCached(tmpv)
		C25519.GeAdd(t, u, tmpv)
		t.ToProjective(r)
	}
	result = new(C25519.Key)
	r.ToBytes(result)
	return result
}
