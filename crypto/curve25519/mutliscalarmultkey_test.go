package curve25519

import (
	"crypto/subtle"
	"fmt"
	C25519 "github.com/deroproject/derosuite/crypto"
	"reflect"
	"testing"
	"unsafe"
)

func TestReflect(t *testing.T) {
	type A struct {
		a int
	}
	var s = A{42}
	var i = int(50)

	rs := reflect.ValueOf(&s).Elem() // s, but writable
	rf := rs.Field(0)                // s.a
	ri := reflect.ValueOf(&i).Elem() // i, but writeable


	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()

	// Now these both work:
	//ri.Set(rf)
	rf.Set(ri)

	fmt.Printf("s: %v\n", s)
}

func TestMultiScalarMultKey(t *testing.T) {
	for i := 0; i < 100; i++ {
		len := 64
		scalarLs := make([]*C25519.Key, len)
		pointLs := make([]*C25519.Key, len)

		for j := 0; j < len; j++ {
			scalarLs[j] = C25519.RandomScalar()
			pointLs[j] = C25519.RandomPubKey()

		}

		res := C25519.ScalarMultKey(pointLs[0], scalarLs[0])

		for j := 1; j < len; j++ {
			tmp := C25519.ScalarMultKey(pointLs[j], scalarLs[j])
			C25519.AddKeys(res, res, tmp)
		}

		resultPrime := MultiScalarMultKey(pointLs, scalarLs)

		resBytes, _ := res.MarshalText()
		resultPrimeBytes, _ := resultPrime.MarshalText()
		ok := subtle.ConstantTimeCompare(resBytes, resultPrimeBytes) == 1
		if !ok {
			t.Fatalf("expected Multi Scalar Mul correct !")
		}
	}
}

func BenchmarkMultiScalarMultKey(b *testing.B) {
	len := 64*32
	scalarLs := make([]*C25519.Key, len)
	pointLs := make([]*C25519.Key, len)

	for j := 0; j < len; j++ {
		scalarLs[j] = C25519.RandomScalar()
		pointLs[j] = C25519.RandomPubKey()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		MultiScalarMultKey(pointLs, scalarLs)
	}
}
