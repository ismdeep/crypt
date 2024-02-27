package aesutil

import (
	"testing"
)

func TestEncryptData(t *testing.T) {
	t.Logf("got = %x", EncryptData(NewKey(), []byte("Hello")))
}
