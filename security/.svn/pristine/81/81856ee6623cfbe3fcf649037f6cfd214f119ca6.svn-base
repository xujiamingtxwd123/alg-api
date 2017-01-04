package TestAlg

import(
	"fmt"
	"security/crypto"
	ckey"security/crypto/key"
	cciher"security/crypto/cipher"
	crsa"security/crypto/rsa"
	chash"security/crypto/hash"
	"strings"
	"crypto/rsa"
	"crypto/rand"
)



func RsaEncTest(index int){
	switch index {
	case 1:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs1,_ := crypto.GetCipherInstance(cciher.ENC_RSA_PKCS1V15)
		pkcs1.Init(cciher.CIPHERMODE_ENCRYPTO,key.GetPublic())
		msg:= []byte{1,2,3,4,5}
		ciphertext,_:=pkcs1.DoFinal(msg)

		pkcs1.Init(cciher.CIPHERMODE_DECRYPTO,key.GetPrivate())
		msg1,_:=pkcs1.DoFinal(ciphertext)
		if(comp(msg,msg1) == true){
			fmt.Println("rsaEncTest1.success")
		}else{
			fmt.Println("false")
		}
	case 2:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs1,_ := crypto.GetCipherInstance(cciher.ENC_RSA_OAEP)
		pkcs1.Init(cciher.CIPHERMODE_ENCRYPTO,key.GetPublic())
		pkcs1.(crsa.RSACipher).SetHashType(chash.HASHTYPE_SHA1)
		msg:= []byte{1,2,3,4,5}
		ciphertext,_:=pkcs1.DoFinal(msg)
		pkcs1.Init(cciher.CIPHERMODE_DECRYPTO,key.GetPrivate())
		pkcs1.(crsa.RSACipher).SetHashType(chash.HASHTYPE_SHA1)
		msg1,_:=pkcs1.DoFinal(ciphertext)

		if(comp(msg,msg1) == true){
			fmt.Println("rsaEncTest2.success")
		}else{
			fmt.Println("false")
		}
	case 3:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs1,_ := crypto.GetCipherInstance(cciher.ENC_RSA_OAEP)
		err:=pkcs1.Init(cciher.CIPHERMODE_ENCRYPTO,key.GetPrivate())
		if(strings.EqualFold(err.Error(),"invaild key type in init")){
			fmt.Println("rsaEncTest3.success")
		}else{
			fmt.Println("false")
		}
	case 4:
		key,_:=rsa.GenerateKey(rand.Reader,1024)
		k1,_:=crypto.BuildKey(ckey.KEYTYPE_RSA_PUBLIC)
		k1.(crsa.RSAPublicKey).SetRSAPublicKey(key.PublicKey)
		k2,_:=crypto.BuildKey(ckey.KEYTYPE_RSA_PRIVATE)
		k2.(crsa.RSAPrivateKey).SetRSAPrivateKey(key)


		//key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs1,_ := crypto.GetCipherInstance(cciher.ENC_RSA_OAEP)
		pkcs1.Init(cciher.CIPHERMODE_ENCRYPTO,k1)
		pkcs1.(crsa.RSACipher).SetHashType(chash.HASHTYPE_SHA1)
		msg:= []byte{1,2,3,4,5}
		ciphertext,_:=pkcs1.DoFinal(msg)
		pkcs1.Init(cciher.CIPHERMODE_DECRYPTO,k2)
		pkcs1.(crsa.RSACipher).SetHashType(chash.HASHTYPE_SHA1)
		msg1,_:=pkcs1.DoFinal(ciphertext)

		if(comp(msg,msg1) == true){
			fmt.Println("rsaEncTest4.success")
		}else{
			fmt.Println("false")
		}


	}
}
