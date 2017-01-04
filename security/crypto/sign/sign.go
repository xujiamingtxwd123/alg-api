package sign

import ckey"security/crypto/key"

type SignType string
const(
//	_
	SIGN_ECDSA SignType = "SIGN_ECDSA"
	SIGN_RSA_PKCS1V15 SignType = "SIGN_RSA_PKCS1V15"
	SIGN_RSA_PSS SignType = "SIGN_RSA_PSS"
	SIGN_ED25519 SignType = "SIGN_ED25519"
	//SIGN_RING_ECDSA
)

type SignAlg interface {
	Init(key ckey.Key) error
	Update(msg []byte) error
	Sign(msg []byte) ([]byte,error)
	Verify(msg []byte, sig []byte) (bool,error)
	Reset()
}