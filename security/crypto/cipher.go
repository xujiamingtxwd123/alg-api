package crypto

import (
	ccipher"security/crypto/cipher"
	crsa"security/crypto/rsa"
	crc4"security/crypto/rc4"
	"errors"
	cmode"security/crypto/cbc_ecb_ctr_ofb_cfb"
	"crypto/aes"
	"crypto/des"
	"security/crypto/gcm"
)

func GetCipherInstance(cipherType ccipher.CipherType) (ccipher.CipherAlg,error){
	switch cipherType {
	case ccipher.ENC_RSA_PKCS1V15:
		return crsa.NewENCPKCS1V15RSA(), nil
	case ccipher.ENC_RSA_OAEP:
		return crsa.NewENCOAEPRSA(), nil
	case ccipher.ENC_RC4:
		return crc4.NewRC4(),nil

	case ccipher.ENC_AES:
		return cmode.NewECB(aes.NewCipher),nil
	case ccipher.ENC_AES_CBC:
		return cmode.NewCBC(aes.NewCipher),nil
	case ccipher.ENC_AES_CFB:
		return cmode.NewCFB(aes.NewCipher),nil
	case ccipher.ENC_AES_CTR:
		return cmode.NewCTR(aes.NewCipher),nil
	case ccipher.ENC_AES_OFB:
		return cmode.NewOFB(aes.NewCipher),nil
	case ccipher.ENC_AES_GCM:
		return gcm.NewGCM(aes.NewCipher),nil
	case ccipher.ENC_DES:
		return cmode.NewECB(des.NewCipher),nil
	case ccipher.ENC_DES_CBC:
		return cmode.NewCBC(des.NewCipher),nil
	case ccipher.ENC_DES_CFB:
		return cmode.NewCFB(des.NewCipher),nil
	case ccipher.ENC_DES_CTR:
		return cmode.NewCTR(des.NewCipher),nil
	case ccipher.ENC_DES_OFB:
		return cmode.NewOFB(des.NewCipher),nil
	case ccipher.ENC_DES_GCM:
		return gcm.NewGCM(des.NewCipher),nil
	case ccipher.ENC_TRIPLE_DES_CBC:
		return  cmode.NewCBC(des.NewTripleDESCipher),nil
	case ccipher.ENC_TRIPLE_DES_CFB:
		return  cmode.NewCFB(des.NewTripleDESCipher),nil
	case ccipher.ENC_TRIPLE_DES_CTR:
		return  cmode.NewCTR(des.NewTripleDESCipher),nil
	case ccipher.ENC_TRIPLE_DES_OFB:
		return  cmode.NewOFB(des.NewTripleDESCipher),nil
	case ccipher.ENC_TRIPLE_DES:
		return cmode.NewECB(des.NewTripleDESCipher),nil	
		
		
	}
	return nil,errors.New("Error: Don't find this cipher type in GetCipherInstance")
}
