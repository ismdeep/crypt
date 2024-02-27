package aesutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/ismdeep/crypt/pkg/core"
)

func TestEncryptAndDecrypt(t *testing.T) {
	key := NewKey()
	fmt.Println(key.String())

	memReader, memWriter := io.Pipe()

	go func() {
		for i := 0; i < 9999; i++ {
			_, err := memWriter.Write(
				[]byte(
					fmt.Sprintf(
						"[%4v] NEW KEY: %v\n",
						i,
						NewKey())))
			core.PanicIf(err)
		}
		core.PanicIf(
			memWriter.Close())
	}()

	pipeReader, pipeWriter := io.Pipe()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()
		Encrypt(key, memReader, pipeWriter)
		if err := pipeWriter.Close(); err != nil {
			panic(err)
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()
		Decrypt(key, pipeReader, os.Stdout)
	}()

	wg.Wait()
}

func TestDecryptData(t *testing.T) {
	plainData := []byte("Hello World.")
	key := NewKey()

	cipherData := EncryptData(key, plainData)

	core.PanicIf(
		core.IfErr(
			string(plainData) != string(DecryptData(key, cipherData)),
			errors.New("assert failed")))
}
