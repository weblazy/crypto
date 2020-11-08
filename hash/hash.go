package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
)

func MD5(text []byte) string {
	hash := md5.New()
	hash.Write(text)
	return hex.EncodeToString(hash.Sum(nil))
}

func SHA256(text []byte) string {
	hash := sha256.New()
	hash.Write(text)
	return hex.EncodeToString(hash.Sum(nil))
}

func SHA512(text []byte) string {
	hash := sha512.New()
	hash.Write(text)
	return hex.EncodeToString(hash.Sum(nil))
}

func FileMD5(file io.Reader) string {
	hash := md5.New()
	_, err := io.Copy(hash, file)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func FileSHA256(filename string) string {
	h := sha256.New()

	f, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HmacValue ...
func Hmac(data []byte, hmacKey []byte) string {
	hash := hmac.New(sha512.New, hmacKey[:])
	hash.Write(data)
	hexDigest := hex.EncodeToString(hash.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(hexDigest))
}
