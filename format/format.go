package format

import (
	"encoding/base64"
	"encoding/hex"
)

type CryptoFormat interface {
	Encode(ciphertext []byte) string
	Decode(ciphertext string) ([]byte, error)
}

type Base64Format struct {
}

type HexFormat struct {
}

func (this *Base64Format) Encode(ciphertext []byte) string {
	return base64.StdEncoding.EncodeToString(ciphertext)
}
func (this *Base64Format) Decode(ciphertext string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(ciphertext)
}

func (this *HexFormat) Encode(ciphertext []byte) string {
	return hex.EncodeToString(ciphertext)
}
func (this *HexFormat) Decode(ciphertext string) ([]byte, error) {
	return hex.DecodeString(ciphertext)
}
