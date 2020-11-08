package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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

// 用私钥对明文进行签名
func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	// 对明文进行sha256散列，生成一个长度为32的字节数组
	digest := sha256.Sum256(data)

	// 通过椭圆曲线方法对散列后的明文进行签名，返回两个big.int类型的大数
	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}
	//将大数转换成字节数组，并拼接起来，形成签名
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// 通过公钥验证签名
func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	// 将明文转换成字节数组
	digest := sha256.Sum256(data)

	//声明两个大数r，s
	r := big.Int{}
	s := big.Int{}
	//将签名平均分割成两部分切片，并将切片转换成*big.int类型
	sigLen := len(signature)
	r.SetBytes(signature[:(sigLen / 2)])
	s.SetBytes(signature[(sigLen / 2):])

	//通过公钥对得到的r，s进行验证
	return ecdsa.Verify(pubkey, digest[:], &r, &s)
}
