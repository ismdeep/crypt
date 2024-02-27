package aesutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/ismdeep/crypt/pkg/core"
)

func Decrypt(key *Key, cipherStreamReader io.Reader, decryptedStreamWriter io.Writer) {
	core.PanicIf(core.IfErr(key == nil, errors.New("invalid key")))

	block, err := aes.NewCipher(key.data)
	core.PanicIf(err)

	iv := make([]byte, IVBlockSize)
	core.PanicIf(core.LastErr(io.ReadFull(cipherStreamReader, iv)))

	stream := cipher.NewCTR(block, iv)
	reader := &cipher.StreamReader{S: stream, R: cipherStreamReader}

	core.PanicIf(core.LastErr(io.Copy(decryptedStreamWriter, reader)))
}

func DecryptData(key *Key, cipherData []byte) []byte {
	bufferReader, bufferWriter := io.Pipe()
	go func() {
		Decrypt(key, bytes.NewReader(cipherData), bufferWriter)
		core.PanicIf(bufferWriter.Close())
	}()
	plainData, err := io.ReadAll(bufferReader)
	core.PanicIf(err)
	return plainData
}
