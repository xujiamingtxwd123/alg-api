package cipher

import (
	ckey"security/crypto/key"
)

type CipherType string
const(
//	_
	ENC_RSA_PKCS1V15 CipherType = "ENC_RSA_PKCS1V15"
	ENC_RSA_OAEP CipherType = "ENC_RSA_OAEP"
	ENC_AES CipherType = "ENC_AES"
	ENC_AES_CBC CipherType = "ENC_AES_CBC"
	ENC_AES_CFB CipherType = "ENC_AES_CFB"
	ENC_AES_CTR CipherType = "ENC_AES_CTR"
	ENC_AES_OFB CipherType = "ENC_AES_OFB"
	ENC_AES_GCM CipherType = "ENC_AES_GCM"

	ENC_DES CipherType = "ENC_DES"
	ENC_DES_CBC CipherType = "ENC_DES_CBC"
	ENC_DES_CFB CipherType = "ENC_DES_CFB"
	ENC_DES_CTR CipherType = "ENC_DES_CTR"
	ENC_DES_OFB CipherType = "ENC_DES_OFB"
	ENC_DES_GCM CipherType = "ENC_DES_GCM"

	ENC_TRIPLE_DES CipherType = "ENC_TRIPLE_DES"
	ENC_TRIPLE_DES_CBC CipherType = "ENC_TRIPLE_DES_CBC"
	ENC_TRIPLE_DES_CFB CipherType = "ENC_TRIPLE_DES_CFB"
	ENC_TRIPLE_DES_CTR CipherType = "ENC_TRIPLE_DES_CTR"
	ENC_TRIPLE_DES_OFB CipherType = "ENC_TRIPLE_DES_OFB"
	//ENC_TRIPLE_DES_GCM
	ENC_RC4 CipherType = "ENC_RC4"
)

type CipherMode int16
const(
//	_
	CIPHERMODE_ENCRYPTO CipherMode = iota
	CIPHERMODE_DECRYPTO
)



type CipherAlg interface {
	Init(mode CipherMode, key ckey.Key) error
	InitIV(mode CipherMode, key ckey.Key, iv []byte) error
	Update(msg []byte) error
	DoFinal(msg []byte) ([]byte,error)
	Reset()
}



