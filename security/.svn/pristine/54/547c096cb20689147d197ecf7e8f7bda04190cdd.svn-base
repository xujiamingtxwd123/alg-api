package ed25519

import(
	"crypto/rand"
	ckey"security/crypto/key"
	"golang.org/x/crypto/ed25519"
	"errors"
//	"fmt"
)

//type ED25519Key struct {
//	PrivKey ed25519.PrivateKey
//	Pubkey ed25519.PublicKey
//}

type ED25519PrivateKey interface {
	ckey.PrivateKey
	GetED25519PrivateKey() (ed25519.PrivateKey)
	SetED25519PrivateKey(ed25519.PrivateKey)
}

type ed25519PrivKey struct {
	priv ed25519.PrivateKey
}

func (rpk *ed25519PrivKey)SetED25519PrivateKey(privkey ed25519.PrivateKey){
	rpk.priv = privkey
}

func (rpk *ed25519PrivKey)GetED25519PrivateKey() (ed25519.PrivateKey){
	return rpk.priv
}


func (rpk *ed25519PrivKey)GetType() ckey.KeyType{
	return ckey.KEYTYPE_ED25519_PRIVATE
}

func (rpk *ed25519PrivKey)ExportKey()([]byte,error){
	return rpk.priv,nil
}

func (rpk *ed25519PrivKey)ImportKey(key []byte) error{
	rpk.priv = key
	return nil
}




type ED25519PublicKey interface {
	ckey.PublicKey
	GetED25519PublicKey() (ed25519.PublicKey)
	SetED25519PublicKey(pubkey ed25519.PublicKey)
}

type ed25519PubKey struct {
	pub ed25519.PublicKey
}

func (rpk *ed25519PubKey)SetED25519PublicKey(pubkey ed25519.PublicKey){
	rpk.pub = pubkey
}

func (rpk *ed25519PubKey)GetED25519PublicKey() (ed25519.PublicKey){
	return rpk.pub
}


func (rpk *ed25519PubKey)GetType() ckey.KeyType{
	return ckey.KEYTYPE_ED25519_PUBLIC
}

func (rpk *ed25519PubKey)ExportKey()([]byte,error){
	return rpk.pub,nil
}

func (rpk *ed25519PubKey)ImportKey(key []byte) error{
	rpk.pub = key
	//fmt.Printf("%x\n",rpk.pub)
	return nil
}

//type ECDSAKeyPair interface {
//	ckey.KeyPair
//}

func (kpk *keypairKey)GetPublic() (ckey.Key){
	return &(kpk.ed25519Pub)
}

func (kpk *keypairKey)GetPrivate() (ckey.Key){
	return &(kpk.ed25519Priv)
}

type keypairKey struct {
	ed25519Priv ed25519PrivKey
	ed25519Pub ed25519PubKey
}

func ED25519KeyPair()(ckey.KeyPair,error){

	key := keypairKey{}
	key.ed25519Pub.pub,key.ed25519Priv.priv,_ = ed25519.GenerateKey(rand.Reader)
	return &key,nil
}

func BuildKey(keyType ckey.KeyType)(ckey.Key,error){
	switch keyType {
	case ckey.KEYTYPE_ED25519_PUBLIC:
		ed25519Pub := ed25519PubKey{}
		return &ed25519Pub,nil
	case ckey.KEYTYPE_ED25519_PRIVATE:
		ed25519Priv := ed25519PrivKey{}
		return &ed25519Priv,nil
	default:
		return nil,errors.New("Error: invalid ecdsa key type in BuildKey")
	}
}