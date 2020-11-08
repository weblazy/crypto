package dsa

import (
	"crypto/dsa"
	"crypto/rand"
	"math/big"
)

// @desc publickey
// @auth liuguoqiang 2020-11-07
// @param
// @return
type PublicKey struct {
	publicKey *dsa.PublicKey
}

// // @desc NewPublicKey
// // @auth liuguoqiang 2020-11-07
// // @param
// // @return
// func NewPublicKey(publicKey string) *PublicKey {
// 	//解码pem格式的公钥，得到公钥的载体block
// 	block, _ := pem.Decode([]byte(publicKey))
// 	if block == nil {
// 		fmt.Printf("%#v\n", errors.New("public key error"))
// 		return nil
// 	}
// 	// 解析得到公钥
// 	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
// 	if err != nil {
// 		fmt.Printf("%#v\n", err)
// 		return nil
// 	}
// 	// 接口类型断言
// 	pub := pubInterface.(*dsa.PublicKey)
// 	return &PublicKey{
// 		publicKey: pub,
// 	}
// }

// @desc PrivateKey
// @auth liuguoqiang 2020-11-07
// @param
// @return
type PrivateKey struct {
	privateKey *dsa.PrivateKey
}

// // @desc NewPrivateKey
// // @auth liuguoqiang 2020-11-07
// // @param
// // @return
// func NewPrivateKey(privateKey string) *PrivateKey {
// 	//解码pem格式的私钥，得到公钥的载体block
// 	block, _ := pem.Decode([]byte(privateKey))
// 	if block == nil {
// 		fmt.Printf("%#v\n", errors.New("private key error!"))
// 		return nil
// 	}

// 	priv, err := x509.Parse()
// 	if err != nil {
// 		fmt.Printf("%#v\n", err)
// 		return nil
// 	}
// 	return &PrivateKey{
// 		privateKey: priv,
// 	}
// }

// func (this *PrivateKey) SetPrivateKeyToPem() string {
// 	stream, err1 := x509.MarshalECPrivateKey(this.privateKey)
// 	if err1 != nil {
// 		return ""
// 	}
// 	block := &pem.Block{
// 		Type:  "ECC PRIVATE KEY",
// 		Bytes: stream,
// 	}

// 	var buf bytes.Buffer
// 	err2 := pem.Encode(&buf, block)
// 	if err2 != nil {
// 		return ""
// 	}

// 	return buf.String()
// }

// func (this *PublicKey) SetPublicKeyToPem() string {
// 	stream, err1 := x509.MarshalPKIXPublicKey(this.publicKey)
// 	if err1 != nil {
// 		return ""
// 	}
// 	block := &pem.Block{
// 		Type:  "ECC PUBLIC KEY",
// 		Bytes: stream,
// 	}

// 	var buf bytes.Buffer
// 	err2 := pem.Encode(&buf, block)
// 	if err2 != nil {
// 		return ""
// 	}

// 	return buf.String()
// }

// @desc
// @auth liuguoqiang 2020-11-08
// @param text-明文的byte形式；privateKey-标准库私钥
// @return 签名r的byte形式；签名s的byte形式
func (this *PrivateKey) Sign(text []byte) ([]byte, []byte) {
	r, s, err := dsa.Sign(rand.Reader, this.privateKey, text)
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
	var r, s big.Int
	err := r.UnmarshalText(rBytes)
	if err != nil {
		return false
	}
	err = s.UnmarshalText(sBytes)
	if err != nil {
		return false
	}
	return dsa.Verify(this.publicKey, text, &r, &s)
}

// @desc 生成公私秘钥
// @auth liuguoqiang 2020-11-08
// @param
// @return
func GenerateKey() (*dsa.PrivateKey, *dsa.PublicKey) {
	//DSA专业做签名和验签
	var param dsa.Parameters //结构体里有三个很大很大的数bigInt
	//结构体实例化
	dsa.GenerateParameters(&param, rand.Reader, dsa.L1024N160) //L是1024，N是160，这里的L是私钥，N是公钥初始参数
	//通过上边参数生成param结构体，里面有三个很大很大的数

	//生成私钥
	var privateKey dsa.PrivateKey //privatekey是个结构体，里面有publickey结构体，该结构体里有Parameters字段
	privateKey.Parameters = param
	//通过随机读数与param一些关系生成私钥
	dsa.GenerateKey(&privateKey, rand.Reader)

	publicKey := privateKey.PublicKey
	return &privateKey, &publicKey
}
