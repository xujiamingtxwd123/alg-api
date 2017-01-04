package crypto

import(
	"errors"
	ckey"security/crypto/key"
	cmac"security/crypto/mac"
	chash"security/crypto/hash"
	chmac"security/crypto/hmac"
)




type MacAlg interface {
	Init(ht chash.HashType, key ckey.Key) error
	Update(msg []byte) error
	DoFinal(msg []byte) ([]byte,error)
	Reset()
	SetHashType(ht chash.HashType) error
}

func GetMacInstance(macType cmac.MacType)(MacAlg,error){
	switch macType {
	case cmac.MACTYPE_HMAC:
		return chmac.NewHMAC(),nil
	default:
		return nil,errors.New("Error: Don't find this mac type in GetCipherInstance")
	}
}
