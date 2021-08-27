package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// RSA RSA结构体
type RSA struct {
	publicKey          string
	privateKey         string
	publicKeyInstance  *rsa.PublicKey
	privateKeyInstance *rsa.PrivateKey
}

// NewRSA 创建RSA实例
func NewRSA() *RSA {
	return &RSA{}
}

// ImportPublicKey 导入RSA公钥
func (receiver *RSA) ImportPublicKey(publicKey string) error {
	//解密pem格式的公钥
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return errors.New("public key error")
	}

	// 解析公钥
	publicKeyInstance, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	// 类型断言
	receiver.publicKeyInstance = publicKeyInstance.(*rsa.PublicKey)
	receiver.publicKey = publicKey

	return nil
}

// ImportPrivateKey 导入RSA私钥
func (receiver *RSA) ImportPrivateKey(privateKey string) error {
	//解密
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return errors.New("private key error")
	}
	//解析PKCS1格式的私钥
	privateKeyInstance, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	receiver.privateKeyInstance = privateKeyInstance
	receiver.privateKey = privateKey

	return nil
}

// Encrypt RSA加密
func (receiver *RSA) Encrypt(plainText string) string {
	data, _ := rsa.EncryptPKCS1v15(rand.Reader, receiver.publicKeyInstance, []byte(plainText))
	return base64.StdEncoding.EncodeToString(data)
}

// Decrypt RSA解密
func (receiver *RSA) Decrypt(cipherText string) string {
	cipherBytes, _ := base64.StdEncoding.DecodeString(cipherText)
	// 解密
	data, _ := rsa.DecryptPKCS1v15(rand.Reader, receiver.privateKeyInstance, cipherBytes)
	return string(data)
}
