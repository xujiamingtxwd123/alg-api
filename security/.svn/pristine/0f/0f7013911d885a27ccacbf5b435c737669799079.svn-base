package crypto


//import "crypto/rsa"

type KeyType string
const(
//	_
	KEYTYPE_ECDSA_PUBLIC KeyType = "KEYTYPE_ECDSA_PUBLIC"
	KEYTYPE_ECDSA_PRIVATE KeyType = "KEYTYPE_ECDSA_PRIVATE"
	KEYTYPE_RSA_PUBLIC KeyType = "KEYTYPE_RSA_PUBLIC"
	KEYTYPE_RSA_PRIVATE KeyType = "KEYTYPE_RSA_PRIVATE"
	KEYTYPE_ED25519_PUBLIC KeyType = "KEYTYPE_ED25519_PUBLIC"
	KEYTYPE_ED25519_PRIVATE KeyType = "KEYTYPE_ED25519_PRIVATE"
	KEYTYPE_DES KeyType = "KEYTYPE_DES"
	KEYTYPE_TRIPLE_DES KeyType = "KEYTYPE_TRIPLE_DES"
	KEYTYPE_RC4 KeyType = "KEYTYPE_RC4"
	KEYTYPE_AES KeyType = "KEYTYPE_AES"
	KEYTYPE_MAC KeyType = "KEYTYPE_MAC"



)

type KeyPairType string
const (
//	_
	KEYPAIRTYPE_RSA KeyPairType = "KEYPAIRTYPE_RSA"
	KEYPAIRTYPE_ECDSA KeyPairType = "KEYPAIRTYPE_ECDSA"
	KEYPAIRTYPE_ED25519 KeyPairType = "KEYPAIRTYPE_ED25519"
)
type KeyLength int16
const(
	KEYLENGTH_ECDSA_P224 KeyLength = 224
	KEYLENGTH_ECDSA_P256 KeyLength = 256
	KEYLENGTH_ECDSA_P384 KeyLength = 384
	KEYLENGTH_ECDSA_P521 KeyLength = 521
	KEYLENGTH_ED25519 KeyLength = 32
)


//type symmkey struct {
//	key []byte
//	kt KeyType
//}
//func (rk *symmkey)SetKey(key []byte) error{
//	rk.key = key
//	return nil
//}
//
//func (rk *symmkey)GetKey() ([]byte,error){
//	return rk.key,nil
//}
//
//func (rk *symmkey)GetType() KeyType{
//	return rk.kt
//}
//
//func BuildKey(keyType KeyType)(Key,error){
//	return &symmkey{kt:keyType},nil
//}



type SymmKey interface {
	Key
	SetKey(key []byte) error
	GetKey()([]byte,error)
}

type Key interface {
	GetType() KeyType

}

type PublicKey interface {
	Key
	//SetPublicKey(PublicKey)
	//GetPublicKey()(PublicKey)
	ExportKey()([]byte,error)
	ImportKey(key []byte) error
}

type PrivateKey interface {
	Key
	//SetPrivateKey(PrivateKey)
	//GetPrivateKey()(PrivateKey)
	ExportKey()([]byte,error)
	ImportKey(key []byte) error
}

type KeyPair interface{
	GetPublic() (Key)
	GetPrivate() (Key)
}




