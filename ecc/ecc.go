package ecc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// @desc publickey
// @auth liuguoqiang 2020-11-07
// @param
// @return
type PublicKey struct {
	publicKey *ecdsa.PublicKey
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
	pub := pubInterface.(*ecdsa.PublicKey)
	return &PublicKey{
		publicKey: pub,
	}
}

// @desc PrivateKey
// @auth liuguoqiang 2020-11-07
// @param
// @return
type PrivateKey struct {
	privateKey *ecdsa.PrivateKey
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

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("%#v\n", err)
		return nil
	}
	return &PrivateKey{
		privateKey: priv,
	}
}

// @desc 生成公私秘钥
// @auth liuguoqiang 2020-11-08
// @param model-曲线类型(默认224, 可选224、256、384、512)
// @return
func GenerateKey(model int) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	var curve elliptic.Curve

	switch model {
	case 224:
		curve = elliptic.P224()
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 512:
		curve = elliptic.P521()
	default:
		curve = elliptic.P224()
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	return privateKey, &publicKey
}

func GenerateKeyEth() (*ecies.PrivateKey, *ecies.PublicKey) {
	privateKey, err := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	return privateKey, &publicKey
}

func (this *PrivateKey) SetPrivateKeyToPem() string {
	stream, err1 := x509.MarshalECPrivateKey(this.privateKey)
	if err1 != nil {
		return ""
	}
	block := &pem.Block{
		Type:  "ECC PRIVATE KEY",
		Bytes: stream,
	}

	var buf bytes.Buffer
	err2 := pem.Encode(&buf, block)
	if err2 != nil {
		return ""
	}

	return buf.String()
}

func (this *PublicKey) SetPublicKeyToPem() string {
	stream, err1 := x509.MarshalPKIXPublicKey(this.publicKey)
	if err1 != nil {
		return ""
	}
	block := &pem.Block{
		Type:  "ECC PUBLIC KEY",
		Bytes: stream,
	}

	var buf bytes.Buffer
	err2 := pem.Encode(&buf, block)
	if err2 != nil {
		return ""
	}

	return buf.String()
}

func (this *PublicKey) Encrypt(text []byte, publicKey *ecies.PublicKey) []byte {
	/*
		@params: text-明文的byte形式；publicKey-以太坊封装的ecc公钥
		@return: 密文的byte形式；错误
	*/
	cipher, err := ecies.Encrypt(rand.Reader, publicKey, text, nil, nil)
	if err != nil {
		return nil
	}
	return cipher
}

func Decrypt(text []byte, privateKey *ecies.PrivateKey) []byte {
	/*
		@params: text-密文的byte形式；privateKey-以太坊封装的ecc私钥
		@return: 明文的byte形式；错误
	*/
	plaint, err := privateKey.Decrypt(text, nil, nil)
	if err != nil {
		return nil
	}
	return plaint
}

// @desc
// @auth liuguoqiang 2020-11-08
// @param text-明文的byte形式；privateKey-标准库私钥
// @return 签名r的byte形式；签名s的byte形式
func (this *PrivateKey) Sign(text []byte) ([]byte, []byte) {
	sha := sha256.New()
	sha.Write(text)
	hash := sha.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hash)
	if err != nil {
		return nil, nil
	}
	rBytes, err := r.MarshalText()
	if err != nil {
		return nil, nil
	}
	sBytes, err := s.MarshalText()
	if err != nil {
		return nil, nil
	}

	return rBytes, sBytes
}

// @desc
// @auth liuguoqiang 2020-11-08
// @param  text-明文的byte形式；签名r的byte形式；签名s的byte形式；publicKey-标准库公钥
// @return
func (this *PublicKey) Verify(text, rBytes, sBytes []byte) bool {
	sha := sha256.New()
	sha.Write(text)
	hash := sha.Sum(nil)

	var r, s big.Int
	err := r.UnmarshalText(rBytes)
	if err != nil {
		return false
	}
	err = s.UnmarshalText(sBytes)
	if err != nil {
		return false
	}

	return ecdsa.Verify(this.publicKey, hash, &r, &s)
}
