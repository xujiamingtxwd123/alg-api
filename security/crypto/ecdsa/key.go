package ecdsa

import(
	"crypto/rand"
	ckey"security/crypto/key"
	"errors"
	"crypto/ecdsa"
	"crypto/elliptic"
//	"crypto/rsa"
	"encoding/json"
	"math/big"
//	"os"
)

type CurveType string

const(
//	_
	P224 CurveType = "P224"
	P256 CurveType = "P256"
	P384 CurveType = "P384"
	P521 CurveType = "P521"
)




type ECDSAPrivateKey interface {
	ckey.PrivateKey
	GetECDSAPrivateKey() (*ecdsa.PrivateKey)
	SetECDSAPrivateKey(*ecdsa.PrivateKey)
	SetCurveType(curveType CurveType)
	GetCurveType() CurveType
}


type innerPrivKey struct {
	//elliptic.Curve
	Curve CurveType
	D *big.Int
}

type ecdsaPrivKey struct {
	priv *ecdsa.PrivateKey
	curveType CurveType
}

func (rpk *ecdsaPrivKey)SetECDSAPrivateKey(privkey *ecdsa.PrivateKey){
	rpk.priv = privkey
}

func (rpk *ecdsaPrivKey)GetECDSAPrivateKey() (*ecdsa.PrivateKey){
	return rpk.priv
}
func (rpk *ecdsaPrivKey)SetCurveType(curveType CurveType){
	rpk.curveType = curveType
}

func (rpk *ecdsaPrivKey)GetCurveType() CurveType{
	return rpk.curveType
}

func (rpk *ecdsaPrivKey)GetType() ckey.KeyType{
	return ckey.KEYTYPE_ECDSA_PRIVATE
}


func (rpk *ecdsaPrivKey)ExportKey()([]byte,error){

	//if(rpk.curveType == 0){
	//	rpk.curveType = P256
	//}
//	fmt.Printf("D:%x\n",rpk.priv.D
//	fmt.Printf("Curve:%x\n",rpk.curveType)


	ecdsapriv := innerPrivKey{rpk.curveType,rpk.priv.D}
//	fmt.Printf("%x\n",ecdsapriv.curveType)
//	aa,_:=json.Marshal(ecdsapriv)
//
//	os.Stdout.Write(aa)
//
//	ecdsapriv1:=innerPrivKey{}
//	json.Unmarshal(aa,&ecdsapriv1)
//	fmt.Printf("fuck:%x\n",ecdsapriv1.D)

	return json.Marshal(ecdsapriv)
}

func (rpk *ecdsaPrivKey)ImportKey(key []byte) error{
	ecdsapriv:=innerPrivKey{}
	err := json.Unmarshal(key,&ecdsapriv)
	if(err == nil){
		if(rpk.priv == nil){
			rpk.priv = &ecdsa.PrivateKey{}
		}
		rpk.priv.D = ecdsapriv.D
		rpk.curveType = (ecdsapriv.Curve)
		rpk.priv.Curve,err = GetCurveType(rpk.curveType)
	}

	return err
}




type innerPubKey struct {
	//elliptic.Curve
	Curve CurveType
	X, Y *big.Int
}



type ECDSAPublicKey interface {
	ckey.PublicKey
	GetECDSAPublicKey() (*ecdsa.PublicKey)
	SetECDSAPublicKey(ecdsa.PublicKey)()
	SetCurveType(curveType CurveType)
	GetCurveType() CurveType
}

type ecdsaPubKey struct {
	pub *ecdsa.PublicKey
	curveType CurveType
}

func (rpk *ecdsaPubKey)GetCurveType() CurveType{
	return rpk.curveType
}


func (rpk *ecdsaPubKey)SetCurveType(curveType CurveType){
	rpk.curveType = curveType
}

func (rpk *ecdsaPubKey)SetECDSAPublicKey(pubkey ecdsa.PublicKey){
	rpk.pub = &pubkey
}

func (rpk *ecdsaPubKey)GetECDSAPublicKey() (*ecdsa.PublicKey){
	return rpk.pub
}


func (rpk *ecdsaPubKey)GetType() ckey.KeyType{
	return ckey.KEYTYPE_ECDSA_PUBLIC
}

func (rpk *ecdsaPubKey)ExportKey()([]byte,error){

	ecdsapub := innerPubKey{rpk.curveType,rpk.pub.X,rpk.pub.Y}
	return json.Marshal(&ecdsapub)
}

func (rpk *ecdsaPubKey)ImportKey(key []byte) error{
	ecdsapub:=innerPubKey{}
	err := json.Unmarshal(key,&ecdsapub)
	if(err == nil){
		if(rpk.pub == nil){
			rpk.pub = &ecdsa.PublicKey{}
		}

		rpk.pub.X = ecdsapub.X
		rpk.pub.Y = ecdsapub.Y
		rpk.curveType = ecdsapub.Curve
		rpk.pub.Curve,err = GetCurveType(rpk.curveType)
	}

	return err
}

//type ECDSAKeyPair interface {
//	ckey.KeyPair
//}

type keypairKey struct {
	ecdsaPriv ecdsaPrivKey
	ecdsaPub ecdsaPubKey
	curveType CurveType
}




func (kpk *keypairKey)GetPublic() (ckey.Key){
	return &(kpk.ecdsaPub)
}

func (kpk *keypairKey)GetPrivate() (ckey.Key){
	return &(kpk.ecdsaPriv)
}

//可以换成函数数组
func GetCurveType(curveType CurveType) (elliptic.Curve,error){
	switch curveType {
	case P224:
		return elliptic.P224(),nil
	case P256:
		return elliptic.P256(),nil
	case P384:
		return elliptic.P384(),nil
	case P521:
		return elliptic.P521(),nil
	default:
		return nil,errors.New("Error: invalid curve type")
	}
}

func ECDSAKeyPair(curveType CurveType) (ckey.KeyPair,error){
	kp :=keypairKey{curveType:curveType}
	ct,err := GetCurveType(curveType)
	if(err != nil){
		return nil,err
	}
	rkp,err := ecdsa.GenerateKey(ct,rand.Reader)
	if(err != nil){
		return nil,err
	}

	kp.ecdsaPriv.priv = rkp
	kp.ecdsaPriv.curveType = curveType


	pk:=ecdsa.PublicKey(rkp.PublicKey)
	kp.ecdsaPub.pub = &pk
	kp.ecdsaPub.curveType = curveType
	return &kp,err
}

//该函数目前用不上 后续看情况
func BuildKey(keyType ckey.KeyType)(ckey.Key,error){
	switch keyType {
	case ckey.KEYTYPE_ECDSA_PUBLIC:
		ecdsaPub := ecdsaPubKey{curveType:P256}
		return &ecdsaPub,nil
	case ckey.KEYTYPE_ECDSA_PRIVATE:
		ecdsaPriv := ecdsaPrivKey{curveType:P256}
		return &ecdsaPriv,nil
	default:
		return nil,errors.New("Error: invalid ecdsa key type in BuildKey")
	}
}


