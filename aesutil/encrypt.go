package aesutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"github.com/ismdeep/crypt/pkg/core"
)

func Encrypt(key *Key, plainReader io.Reader, encryptedStreamWriter io.Writer) {
	core.PanicIf(core.IfErr(key == nil, errors.New("key is empty")))

	block, err := aes.NewCipher(key.data)
	core.PanicIf(err)

	bufferReader, bufferWriter := io.Pipe()

	iv := make([]byte, IVBlockSize)
	core.PanicIf(core.LastErr(io.ReadFull(rand.Reader, iv)))

	stream := cipher.NewCTR(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: bufferWriter}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()
		core.PanicIf(core.LastErr(io.Copy(encryptedStreamWriter, bufferReader)))
	}()

	core.PanicIf(
		core.LastErr(
			bufferWriter.Write(iv)))

	core.PanicIf(
		core.LastErr(
			io.Copy(writer, plainReader)))

	core.PanicIf(bufferWriter.Close())

	wg.Wait()
}

func EncryptData(key *Key, plainData []byte) []byte {
	bufferReader, bufferWriter := io.Pipe()
	go func() {
		Encrypt(key, bytes.NewReader(plainData), bufferWriter)
		core.PanicIf(bufferWriter.Close())
	}()

	encryptData, err := io.ReadAll(bufferReader)
	core.PanicIf(err)
	return encryptData
}
