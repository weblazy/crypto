package rc4

import (
	"crypto/rc4"
)

// @desc rc4加解密
// @auth liuguoqiang 2020-11-07
// @param
// @return
func Encode(src []byte, key []byte) ([]byte, error) {
	rc4obj, err := rc4.NewCipher(key) //返回 cipher
	if err != nil {
		return []byte(""), err
	}
	dst := make([]byte, len(src))
	//XORKeyStream方法将src的数据与秘钥生成的伪随机位流取XOR并写入dst。
	rc4obj.XORKeyStream(dst, src)
	//dst就是你加密的返回过来的结果了，注意：dst为base-16 编码的字符串，每个字节使用2个字符表示 必须格式化成字符串
	return dst, nil
}
