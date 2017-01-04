package crypto

import (
	csign"security/crypto/sign"
//	"security/crypto/ecdsa"
	"errors"
	crsa"security/crypto/rsa"
//	"golang.org/x/crypto/ed25519"
	cecdsa"security/crypto/ecdsa"
	ced25519"security/crypto/ed25519"
//	cring_sign"security/crypto/ring_sign"
)


func GetSignInstance(signType csign.SignType) (csign.SignAlg,error){
	switch signType {
	case csign.SIGN_ECDSA:
		return cecdsa.NewECDSA(),nil
	case csign.SIGN_RSA_PKCS1V15:
		return crsa.NewSignPKCS1V15RSA(),nil
	case csign.SIGN_RSA_PSS:
		return crsa.NewSignPSSRSA(),nil
	case csign.SIGN_ED25519:
		return ced25519.NewED25519(),nil
	//case csign.SIGN_RING_ECDSA:
	//	return cring_sign.NewPublicKeyRing()
	default:
		return nil,errors.New("Error: Don't find this sign type in GetSignInstance")
	}
	return nil,nil
}

