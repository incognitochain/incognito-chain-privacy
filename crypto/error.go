package crypto

import "errors"

var InvalidMaxHashSizeErr = errors.New("invalid max hash size")
var InvalidHashSizeErr = errors.New("invalid hash size")
var NilHashErr = errors.New("input hash is nil")