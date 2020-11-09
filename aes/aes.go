package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/weblazy/crypto/format"
	"github.com/weblazy/crypto/mode"
	"github.com/weblazy/crypto/padding"
)

// @desc aes
// @auth liuguoqiang 2020-11-07
// @param
// @return
type Aes struct {
	key     []byte
	vector  []byte
	block   cipher.Block
	mode    mode.CryptoMode
	padding padding.CryptoPadding
	format  format.CryptoFormat
}

// @desc NewAes
// @auth liuguoqiang 2020-11-07
// @param key 4字节的任意倍数，最小值为16字节，最大值为32字节
// @return
func NewAes(key []byte) *Aes {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	return &Aes{
		key:     key,
		block:   block,
		vector:  key[:block.BlockSize()],
		mode:    &mode.CBCMode{},
		padding: &padding.PKCS5Padding{},
		format:  &format.Base64Format{},
	}
}

func (this *Aes) WithMode(cryptoMode mode.CryptoMode) *Aes {
	this.mode = cryptoMode
	return this
}

func (this *Aes) WithPadding(cryptoPadding padding.CryptoPadding) *Aes {
	this.padding = cryptoPadding
	return this
}

func (this *Aes) WithFormat(cryptoFormat format.CryptoFormat) *Aes {
	this.format = cryptoFormat
	return this
}

func (this *Aes) WithVector(vector []byte) *Aes {
	this.vector = vector
	return this
}

// @desc aes加密
// @auth liuguoqiang 2020-11-07
// @param
// @return
func (this *Aes) Encrypt(origData string) (string, error) {
	data := []byte(origData)
	// padding
	data = this.padding.Padding(data, this.block.BlockSize())
	// mode
	ciphertext, err := this.mode.Encrypt(this.block, data, this.key, this.vector)
	if err != nil {
		return "", err
	}
	// format
	return this.format.Encode(ciphertext), nil
}

// @desc aes解密
// @auth liuguoqiang 2020-11-07
// @param
// @return
func (this *Aes) Decrypt(data string) (string, error) {
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
