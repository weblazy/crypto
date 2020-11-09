package ripemd160

import (
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

func Ripemd160(src []byte) string {
	//创建ripemd160算法加密块
	hasher := ripemd160.New()
	//将明文写入加密块
	hasher.Write(src)
	//通过加密块的方法对写入的明文进行加密，传参nil，表示没有新的信息和加密后的hash进行组合
	hashBytes := hasher.Sum(nil)
	//字节转成字符串
	return fmt.Sprintf("%x", hashBytes)
}
