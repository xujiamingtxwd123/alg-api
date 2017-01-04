package crypto

import (
	crsa"security/crypto/rsa"
	ckey"security/crypto/key"
	cecdsa"security/crypto/ecdsa"
	ced25519"security/crypto/ed25519"
	crc4"security/crypto/rc4"
	cmode"security/crypto/cbc_ecb_ctr_ofb_cfb"
	chmac"security/crypto/hmac"
	"errors"
)


func KeyPair(keyType ckey.KeyPairType, keyLength ckey.KeyLength) (ckey.KeyPair,error){

	switch keyType {
	case ckey.KEYPAIRTYPE_RSA:
		return crsa.RSAKeyPair(int(keyLength))
	case ckey.KEYPAIRTYPE_ECDSA:
		switch keyLength {
		case ckey.KEYLENGTH_ECDSA_P224:
			return cecdsa.ECDSAKeyPair(cecdsa.P224)
		case ckey.KEYLENGTH_ECDSA_P256:
			return cecdsa.ECDSAKeyPair(cecdsa.P256)
		case ckey.KEYLENGTH_ECDSA_P384:
			return cecdsa.ECDSAKeyPair(cecdsa.P384)
		case ckey.KEYLENGTH_ECDSA_P521:
			return cecdsa.ECDSAKeyPair(cecdsa.P521)
		default:
			return nil,errors.New("Error: invalid ecdsa key type in keypair")
		}
	case ckey.KEYPAIRTYPE_ED25519:
		return ced25519.ED25519KeyPair()
	default:
		return nil,errors.New("Error: invalid key type in keypair")
	}
	return nil,nil
}

func BuildKey(keyType ckey.KeyType) (ckey.Key,error){
	switch keyType {
	case ckey.KEYTYPE_RSA_PUBLIC:
		return crsa.BuildKey(keyType)
	case ckey.KEYTYPE_RSA_PRIVATE:
		return crsa.BuildKey(keyType)
	case ckey.KEYTYPE_RC4:
		return crc4.BuildKey(keyType)
	case ckey.KEYTYPE_ECDSA_PRIVATE:
		return cecdsa.BuildKey(keyType)
	case ckey.KEYTYPE_ECDSA_PUBLIC:
		return cecdsa.BuildKey(keyType)
	case ckey.KEYTYPE_ED25519_PRIVATE:
		return ced25519.BuildKey(keyType)
	case ckey.KEYTYPE_ED25519_PUBLIC:
		return ced25519.BuildKey(keyType)
	case ckey.KEYTYPE_DES:
		return cmode.BuildKey(keyType)
	case ckey.KEYTYPE_TRIPLE_DES:
		return cmode.BuildKey(keyType)
	case ckey.KEYTYPE_AES:
		return cmode.BuildKey(keyType)
	case ckey.KEYTYPE_MAC:
		return chmac.BuildKey(keyType)
	default:
		return nil,errors.New("Error: invalid key type in BuildKey")
	}
}