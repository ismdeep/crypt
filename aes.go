package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// AESModeCBC 密码分组链接模式（Cipher Block Chaining (CBC)）
const AESModeCBC = "cbc"

// AESModeCTR 计算器模式（Counter (CTR)）
const AESModeCTR = "ctr"

// AESModeCFB 密码反馈模式（Cipher FeedBack (CFB)）
const AESModeCFB = "cfb"

// AESModeOFB 输出反馈模式（Output FeedBack (OFB)）
const AESModeOFB = "ofb"

// AES AES结构体
type AES struct {
	Key   string
	Mode  string
	block cipher.Block
}

// GenAESKey 生成AES密钥
func GenAESKey() string {
	// Hex generate hex bytes
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// NewAES 创建AES实例
func NewAES(key string, mode string) (*AES, error) {
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	if mode != AESModeCBC && mode != AESModeCTR && mode != AESModeCFB && mode != AESModeOFB {
		return nil, errors.New("invalid mode")
	}

	return &AES{
		Key:   key,
		Mode:  mode,
		block: block,
	}, nil

}

// Encrypt AES加密
func (receiver *AES) Encrypt(plainText string) string {
	if receiver.Mode == AESModeCBC {
		return cbcEncrypt(receiver.Key, receiver.block, plainText)
	}

	if receiver.Mode == AESModeCTR {
		return crtEncrypt(plainText, receiver.block)
	}

	if receiver.Mode == AESModeCFB {
		return cfbEncrypt(plainText, receiver.Key)
	}

	if receiver.Mode == AESModeOFB {
		return ofbEncrypt(plainText, receiver.block)
	}

	return ""
}

// Decrypt AES解密
func (receiver *AES) Decrypt(cipherText string) string {
	if receiver.Mode == AESModeCBC {
		return cbcDecrypt(cipherText, receiver.Key)
	}

	if receiver.Mode == AESModeCTR {
		return crtDecrypt(cipherText, receiver.block)
	}

	if receiver.Mode == AESModeCFB {
		return cfbDecrypt(cipherText, receiver.Key)
	}

	if receiver.Mode == AESModeOFB {
		return ofbDecrypt(cipherText, receiver.block)
	}

	return ""
}
