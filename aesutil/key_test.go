package aesutil

import (
	"errors"
	"testing"

	"github.com/ismdeep/crypt/pkg/core"
)

func TestNewKey(t *testing.T) {
	t.Logf("got = %v", NewKey().String())
}

func TestParseKey(t *testing.T) {
	key := NewKey()
	t.Logf("key = %v", key.String())
	t.Logf("got = %v", ParseKey(key.String()).String())
	core.PanicIf(
		core.IfErr(
			key.String() != ParseKey(key.String()).String(), errors.New("assert equal failed")))
}
