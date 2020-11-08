package des

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/weblazy/crypto/format"
	"github.com/weblazy/crypto/mode"
	"github.com/weblazy/crypto/padding"
)

// @desc des
// @auth liuguoqiang 2020-11-07
// @param
// @return
type Des struct {
	key     []byte
	vector  []byte
	block   cipher.Block
	mode    mode.CryptoMode
	padding padding.CryptoPadding
	format  format.CryptoFormat
}

// @desc NewDes
// @auth liuguoqiang 2020-11-07
// @param key 8字节
// @return
func NewDes(key []byte) *Des {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}
	return &Des{
		key:     key,
		block:   block,
		vector:  key[:block.BlockSize()],
		mode:    &mode.CBCMode{},
		padding: &padding.PKCS5Padding{},
		format:  &format.Base64Format{},
	}
}

func (this *Des) WithMode(cryptoMode mode.CryptoMode) *Des {
	this.mode = cryptoMode
	return this
}

func (this *Des) WithPadding(cryptoPadding padding.CryptoPadding) *Des {
	this.padding = cryptoPadding
	return this
}

func (this *Des) WithFormat(cryptoFormat format.CryptoFormat) *Des {
	this.format = cryptoFormat
	return this
}

func (this *Des) WithVector(vector []byte) *Des {
	this.vector = vector
	return this
}

// @desc des加密
// @auth liuguoqiang 2020-11-07
// @param
// @return
func (this *Des) Encrypt(origData string) (string, error) {
	data := []byte(origData)
	// padding
	data = this.padding.Padding(data, this.block.BlockSize())
	// mod
	ciphertext, err := this.mode.Encrypt(this.block, data, this.key, this.vector)
	if err != nil {
		return "", err
	}
	// format
	return this.format.Encode(ciphertext), nil
}

// @desc des解密
// @auth liuguoqiang 2020-11-07
// @param
// @return
func (this *Des) Decrypt(data string) (string, error) {
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
