package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

func cfbEncrypt(plainText string, key string) string {
	k := []byte(key)
	plainBytes := []byte(plainText)
	block, _ := aes.NewCipher(k)
	cipherBytes := make([]byte, aes.BlockSize+len(plainBytes))
	iv := cipherBytes[:aes.BlockSize]
	_, _ = io.ReadFull(rand.Reader, iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherBytes[aes.BlockSize:], plainBytes)

	return base64.StdEncoding.EncodeToString(cipherBytes)
}

func cfbDecrypt(cipherText string, key string) string {
	k := []byte(key)
	encrypted, _ := base64.StdEncoding.DecodeString(cipherText)
	block, _ := aes.NewCipher(k)
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return string(encrypted)
}
