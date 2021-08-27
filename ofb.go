package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

func ofbEncrypt(plainText string, block cipher.Block) string {
	data := []byte(plainText)
	data = pkcs7Padding(data, aes.BlockSize)
	out := make([]byte, aes.BlockSize+len(data))
	iv := out[:aes.BlockSize]
	_, _ = io.ReadFull(rand.Reader, iv)
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(out[aes.BlockSize:], data)
	return base64.StdEncoding.EncodeToString(out)
}

func ofbDecrypt(cipherText string, block cipher.Block) string {
	data, _ := base64.StdEncoding.DecodeString(cipherText)
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	out := make([]byte, len(data))
	mode := cipher.NewOFB(block, iv)
	mode.XORKeyStream(out, data)
	out = pkcs7UnPadding(out)
	return string(out)
}
