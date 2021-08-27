package crypt

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
)

//加密
func crtEncrypt(plainText string, block cipher.Block) string {
	plainBytes := []byte(plainText)

	//2. 创建分组模式，在crypto/cipher包中
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	//3. 加密
	dst := make([]byte, len(plainBytes))
	stream.XORKeyStream(dst, plainBytes)

	return base64.StdEncoding.EncodeToString(dst)
}

// 解密
func crtDecrypt(cipherText string, block cipher.Block) string {
	// 转成字节数组
	cipherBytes, _ := base64.StdEncoding.DecodeString(cipherText)

	//2. 创建分组模式，在crypto/cipher包中
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	//3. 加密
	dst := make([]byte, len(cipherBytes))
	stream.XORKeyStream(dst, cipherBytes)

	return string(dst)
}
