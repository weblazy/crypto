package padding

import (
	"bytes"
)

// 某些加密算法要求明文需要按一定长度对齐，叫做块大小(BlockSize)，比如16字节，那么对于一段任意的数据，加密前需要对最后一个块填充到16 字节，解密后需要删除掉填充的数据。
// ZeroPadding，数据长度不对齐时使用0填充，否则不填充。
// PKCS7Padding，假设数据长度需要填充n(n>0)个字节才对齐，那么填充n个字节，每个字节都是n;如果数据本身就已经对齐了，则填充一块长度为块大小的数据，每个字节都是块大小。
// PKCS5Padding，PKCS7Padding的子集，块大小固定为8字节。
// 由于使用PKCS7Padding/PKCS5Padding填充时，最后一个字节肯定为填充数据的长度，所以在解密后可以准确删除填充的数据，而使用ZeroPadding填充时，没办法区分真实数据与填充数据，所以只适合以\0结尾的字符串加解密。

type CryptoPadding interface {
	Padding(ciphertext []byte, blockSize int) []byte
	UnPadding(origData []byte) []byte
}

type PKCS5Padding struct {
}

type ZeroPadding struct {
}

func (this *PKCS5Padding) Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (this *PKCS5Padding) UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func (this *ZeroPadding) Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func (this *ZeroPadding) UnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}
