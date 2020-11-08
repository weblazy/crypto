package tripledes

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/weblazy/crypto/format"
	"github.com/weblazy/crypto/mode"
	"github.com/weblazy/crypto/padding"
)

// @desc 3des
// @auth liuguoqiang 2020-11-07
// @param
// @return
type TripleDes struct {
	key     []byte
	vector  []byte
	block   cipher.Block
	mode    mode.CryptoMode
	padding padding.CryptoPadding
	format  format.CryptoFormat
}

// @desc NewTripleDes
// @auth liuguoqiang 2020-11-07
// @param key 3des的密钥长度必须为24位
// @return
func NewTripleDes(key []byte) *TripleDes {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil
	}
	return &TripleDes{
		key:     key,
		block:   block,
		vector:  key[:block.BlockSize()],
		mode:    &mode.CBCMode{},
		padding: &padding.PKCS5Padding{},
		format:  &format.Base64Format{},
	}
}

func (this *TripleDes) WithMode(cryptoMode mode.CryptoMode) *TripleDes {
	this.mode = cryptoMode
	return this
}

func (this *TripleDes) WithPadding(cryptoPadding padding.CryptoPadding) *TripleDes {
	this.padding = cryptoPadding
	return this
}

func (this *TripleDes) WithFormat(cryptoFormat format.CryptoFormat) *TripleDes {
	this.format = cryptoFormat
	return this
}

func (this *TripleDes) WithVector(vector []byte) *TripleDes {
	this.vector = vector
	return this
}

// @desc 3des加密
// @auth liuguoqiang 2020-11-07
// @param
// @return
func (this *TripleDes) TripleEncrypt(origData string) (string, error) {
	data := []byte(origData)
	//padding
	data = this.padding.Padding(data, this.block.BlockSize())
	//mod
	ciphertext, err := this.mode.Encrypt(this.block, data, this.key, this.vector)
	if err != nil {
		return "", err
	}
	//format
	return this.format.Encode(ciphertext), nil
}

// @desc 3des解密
// @auth liuguoqiang 2020-11-07
// @param
// @return
func (this *TripleDes) TrileDesDecrypt(data string) (string, error) {
	// format
	ciphertext, err := this.format.Decode(data)
	if err != nil {
		return "", err
	}
	// mode
	origData, err := this.mode.Decrypt(this.block, ciphertext, this.key, this.vector)
	if err != nil {
		return "", err
	}
	// padding
	return string(this.padding.UnPadding(origData)), nil
}
