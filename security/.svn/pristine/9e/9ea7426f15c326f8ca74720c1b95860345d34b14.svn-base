package TestAlg

import "security/crypto"
import ckey"security/crypto/key"
import (
	crsa "security/crypto/rsa"
	ccipher"security/crypto/cipher"
	chash"security/crypto/hash"
	"fmt"
	"crypto/rsa"
	"crypto/rand"
	xed"golang.org/x/crypto/ed25519"
	ced25519"security/crypto/ed25519"
	csign"security/crypto/sign"
	"crypto/elliptic"
	"crypto/ecdsa"
	cecdsa"security/crypto/ecdsa"
	r"math/rand"
//	"encoding/json"
)

func KeyImportExport(index int){
	switch index {
	case 1:

		k,_:=rsa.GenerateKey(rand.Reader,1024)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_RSA_PUBLIC)
		ko.(crsa.RSAPublicKey).SetRSAPublicKey(k.PublicKey)

		ko1,_:=crypto.BuildKey(ckey.KEYTYPE_RSA_PRIVATE)
		ko1.(crsa.RSAPrivateKey).SetRSAPrivateKey(k)


		//ab,_:=json.Marshal(ko)
		//fmt.Printf("%x\n", ab)

		exportPubKey,_:=ko.(ckey.PublicKey).ExportKey()
		exportPrivKey,_:=ko1.(ckey.PrivateKey).ExportKey()

		//fmt.Printf("%x\n",exportPubKey)
		//fmt.Printf("%x\n",exportPrivKey)

		k2,_:=crypto.BuildKey(ckey.KEYTYPE_RSA_PUBLIC)
		k3,_:=crypto.BuildKey(ckey.KEYTYPE_RSA_PRIVATE)

		k2.(ckey.PublicKey).ImportKey(exportPubKey)
		k3.(ckey.PrivateKey).ImportKey(exportPrivKey)


		pkcs1,_ := crypto.GetCipherInstance(ccipher.ENC_RSA_OAEP)
		pkcs1.Init(ccipher.CIPHERMODE_ENCRYPTO,k2)
		pkcs1.(crsa.RSACipher).SetHashType(chash.HASHTYPE_SHA1)
		msg:= []byte{1,2,3,4,5}
		ciphertext,_:=pkcs1.DoFinal(msg)
		pkcs1.Init(ccipher.CIPHERMODE_DECRYPTO,k3)
		pkcs1.(crsa.RSACipher).SetHashType(chash.HASHTYPE_SHA1)
		msg1,_:=pkcs1.DoFinal(ciphertext)

		if(comp(msg,msg1) == true){
			fmt.Println("KeyImportExport1.success")
		}else{
			fmt.Println("false")
		}

	case 2:
		//key,_:=crypto.KeyPair(ckey.KEYPAIRTYPE_ED25519,ckey.KEYLENGTH_ED25519)
		k1,k5,_:=xed.GenerateKey(rand.Reader)
		key,_:=crypto.BuildKey(ckey.KEYTYPE_ED25519_PRIVATE)
		key.(ced25519.ED25519PrivateKey).SetED25519PrivateKey(k5)

		key1,_:=crypto.BuildKey(ckey.KEYTYPE_ED25519_PUBLIC)
		key1.(ced25519.ED25519PublicKey).SetED25519PublicKey(k1)


		exportPrivKey,_:=key.(ckey.PublicKey).ExportKey()
		exportPubKey,_:=key1.(ckey.PrivateKey).ExportKey()

		//fmt.Printf("%x\n",exportPubKey)
		//fmt.Printf("%x\n",exportPrivKey)

		k2,_:=crypto.BuildKey(ckey.KEYTYPE_ED25519_PUBLIC)
		k3,_:=crypto.BuildKey(ckey.KEYTYPE_ED25519_PRIVATE)

		k2.(ckey.PublicKey).ImportKey(exportPubKey)
		k3.(ckey.PrivateKey).ImportKey(exportPrivKey)


		ed,_:=crypto.GetSignInstance(csign.SIGN_ED25519)
		ed.Init(k3)
		msg:=[]byte{1,2,3,4,5,6,7,8,9}
		dst,_ := ed.Sign(msg)

		ed.Init(k2)
		result,_:=ed.Verify(msg,dst)

		if(result == true){
			fmt.Println("KeyImportExport2.success")
		}else{
			fmt.Println("false")
		}

	case 3:

		k1,_:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)

		cp,_ := crypto.GetSignInstance(csign.SIGN_ECDSA)
		k2,_:=crypto.BuildKey(ckey.KEYTYPE_ECDSA_PRIVATE)
		k2.(cecdsa.ECDSAPrivateKey).SetECDSAPrivateKey(k1)
		//k2.(cecdsa.ECDSAPrivateKey).SetCurveType(cecdsa.P256)

		k3,_:=crypto.BuildKey(ckey.KEYTYPE_ECDSA_PUBLIC)
		k3.(cecdsa.ECDSAPublicKey).SetECDSAPublicKey(k1.PublicKey)
		//k2.(cecdsa.ECDSAPrivateKey).SetCurveType(cecdsa.P256)


		priv,_:=k2.(cecdsa.ECDSAPrivateKey).ExportKey()
		pub,_:=k3.(cecdsa.ECDSAPublicKey).ExportKey()

//		fmt.Printf("%x\n",priv)
//		fmt.Printf("%x\n",pub)
		k4,_:=crypto.BuildKey(ckey.KEYTYPE_ECDSA_PRIVATE)
		k5,_:=crypto.BuildKey(ckey.KEYTYPE_ECDSA_PUBLIC)


		k4.(cecdsa.ECDSAPrivateKey).ImportKey(priv)
		k5.(cecdsa.ECDSAPublicKey).ImportKey(pub)

		err := cp.Init(k4)
		msg := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}
		sig,err1 := cp.Sign(msg)

		//fmt.Println(err1)
		//fmt.Printf("sig:%x\n",sig)
		cp.Init(k5)
		result,_ := cp.Verify(msg,sig)
		//fmt.Println(err2)

		if((err1 == nil) && (len(sig) > 0)&&( result == true)){
			fmt.Println("KeyImportExport3.success")
		}else{
			fmt.Println(err)
		}




	}
}
