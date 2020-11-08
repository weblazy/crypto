package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
)

// @desc publickey
// @auth liuguoqiang 2020-11-07
// @param
// @return
type PublicKey struct {
	publicKey *rsa.PublicKey
}

// @desc NewPublicKey
// @auth liuguoqiang 2020-11-07
// @param
// @return
func NewPublicKey(publicKey string) *PublicKey {
	//解码pem格式的公钥，得到公钥的载体block
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		fmt.Printf("%#v\n", errors.New("public key error"))
		return nil
	}
	// 解析得到公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("%#v\n", err)
		return nil
	}
	// 接口类型断言
	pub := pubInterface.(*rsa.PublicKey)
	return &PublicKey{
		publicKey: pub,
	}
}

// @desc PrivateKey
// @auth liuguoqiang 2020-11-07
// @param
// @return
type PrivateKey struct {
	privateKey *rsa.PrivateKey
}

// @desc NewPrivateKey
// @auth liuguoqiang 2020-11-07
// @param
// @return
func NewPrivateKey(privateKey string) *PrivateKey {
	//解码pem格式的私钥，得到公钥的载体block
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		fmt.Printf("%#v\n", errors.New("private key error!"))
		return nil
	}
	//解析得到PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("%#v\n", err)
		return nil
	}
	return &PrivateKey{
		privateKey: priv,
	}
}

// @desc  generate rsa privateKey publicKey
// @auth liuguoqiang 2020-11-08
// @param
// @return
func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil
	}
	publicKey := privateKey.PublicKey
	return privateKey, &publicKey
}

// @desc 获取公钥的指数和模数
// @auth liuguoqiang 2020-11-08
// @param
// @return
func (this *PublicKey) GetEN() (string, string) {
	return strconv.FormatInt(int64(this.publicKey.E), 16), this.publicKey.N.Text(16)
}

// @desc 获取设置指数和模数生成公钥
// @auth liuguoqiang 2020-11-08
// @param
// @return
func SetEN(exp, mod string) *rsa.PublicKey {
	e, err1 := strconv.ParseInt(exp, 16, 0)
	if err1 != nil {
		return nil
	}
	bigN := new(big.Int)
	bigN, err2 := bigN.SetString(mod, 16)
	if err2 != true {
		return nil
	}
	return &rsa.PublicKey{
		N: bigN,
		E: int(e),
	}
}

func (this *PrivateKey) SetPrivateKeyToPem() string {
	stream := x509.MarshalPKCS1PrivateKey(this.privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: stream,
	}

	var buf bytes.Buffer
	err := pem.Encode(&buf, block)
	if err != nil {
		return ""
	}
	return buf.String()
}

func (this *PublicKey) SetPublicKeyToPem() string {
	stream := x509.MarshalPKCS1PublicKey(this.publicKey)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: stream,
	}
	var buf bytes.Buffer
	err := pem.Encode(&buf, block)
	if err != nil {
		return ""
	}
	return buf.String()
}

// @desc rsa sign
// @auth liuguoqiang 2020-11-08
// @param
// @return
func (this *PrivateKey) Sign(text []byte) []byte {
	hash := sha256.New()
	hash.Write(text)
	signature, err := rsa.SignPKCS1v15(rand.Reader, this.privateKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return nil
	}
	return signature
}

// @desc rsa sign verify
// @auth liuguoqiang 2020-11-08
// @param
// @return
func (this *PublicKey) Verify(text, sign []byte) bool {
	hash := sha256.New()
	hash.Write(text)
	err := rsa.VerifyPKCS1v15(this.publicKey, crypto.SHA256, hash.Sum(nil), sign)
	if err != nil {
		return false
	}
	return true
}

// @desc 加密
// @auth liuguoqiang 2020-11-08
// @param
// @return
func (this *PublicKey) Encrypt(origData []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, this.publicKey, origData)
}

// @desc  解密
// @auth liuguoqiang 2020-11-08
// @param
// @return
func (this *PrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, this.privateKey, ciphertext)
}