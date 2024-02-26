package aesutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ismdeep/crypt/pkg/core"
)

const (
	IVBlockSize = 16
	KeySize     = 32
)

type Key struct {
	data []byte
}

func NewKey() *Key {
	key := make([]byte, KeySize)

	core.PanicIf(core.LastErr(rand.Read(key)))

	return &Key{
		data: key,
	}
}

func ParseKey(s string) *Key {
	core.PanicIf(
		core.IfErr(strings.Index(s, "ak_") != 0, errors.New("bad key format")))

	data, err := hex.DecodeString(s[3:])
	core.PanicIf(err)

	return &Key{data: data}
}

func (receiver *Key) String() string {
	return "ak_" + hex.EncodeToString(receiver.data)
}
