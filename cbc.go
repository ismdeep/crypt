package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

func cbcEncrypt(key string, block cipher.Block, plainText string) string {
	k := []byte(key)
	// 分组秘钥

	plainBytes := []byte(plainText)

	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	plainBytes = pkcs7Padding(plainBytes, blockSize)
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// 创建数组
	cipherBytes := make([]byte, len(plainBytes))
	// 加密
	blockMode.CryptBlocks(cipherBytes, plainBytes)

	return base64.StdEncoding.EncodeToString(cipherBytes)
}

func cbcDecrypt(cipherText string, key string) string {
	// 转成字节数组
	cipherBytes, _ := base64.StdEncoding.DecodeString(cipherText)
	k := []byte(key)
	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(cipherBytes))
	// 解密
	blockMode.CryptBlocks(orig, cipherBytes)
	// 去补全码
	orig = pkcs7UnPadding(orig)
	return string(orig)
}
