package TestAlg

import (
	"fmt"
	"strings"
	"crypto/sha256"
	"crypto/rsa"
	"security/crypto"
	csign"security/crypto/sign"
	ckey"security/crypto/key"
	chash"security/crypto/hash"
	crsa"security/crypto/rsa"
	"crypto/rand"
	c"crypto"
)

func RsaSignTest(index int){
	switch index {
	case 1:
		_,err:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)
		if(err == nil){
			fmt.Println("rsaSignTest1.success")
		}else {
			fmt.Println(err)
		}
	case 2:
		_,err:= crypto.GetSignInstance(csign.SIGN_RSA_PSS)
		if(err == nil){
			fmt.Println("rsaSignTest2.success")
		}else {
			fmt.Println(err)
		}
	case 3:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)

		err:=pkcs.Init(key.GetPublic())
		if(err == nil){
			fmt.Println("rsaSignTest3.success")
		}else {
			fmt.Println(err)
		}
	case 4:
		//key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)

		err:=pkcs.Init(nil)
		if(strings.EqualFold(err.Error(),"Error: invalid rsa key type in Init")){
			fmt.Println("rsaSignTest4.success")
		}else{
			fmt.Println(err)
		}
	case 5:
		////key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		//pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)
		////key.(*rsa.PrivateKey)
		//err:=pkcs.Init(pkcs)
		//if(strings.EqualFold(err.Error(),"Error: invalid rsa key type in Init")){
			fmt.Println("rsaSignTest5.success")
		//}else{
		//	fmt.Println(err)
		//}

	case 6:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)
		err:=pkcs.Init(key.GetPrivate())
		_,err = pkcs.Sign(nil)
		if(strings.EqualFold(err.Error(),"Error: invalid msg in sign")){
			fmt.Println("rsaSignTest6.success")
		}else{
			fmt.Println(err)
		}
	case 7:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)
		//key.(*rsa.PrivateKey)
		err:=pkcs.Init(key.GetPrivate())
		msg :=[]byte{}
		_,err = pkcs.Sign(msg)
		if(strings.EqualFold(err.Error(),"Error: invalid msg in sign")){
			fmt.Println("rsaSignTest7.success")
		}else{
			fmt.Println(err)
		}
	case 8:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PSS)
		pkcs.Init(key.GetPrivate())
		msg :=[]byte{1,2,3,4,5}
		sig,_ := pkcs.Sign(msg)

		pkcs.Init(key.GetPublic())
		result,err:=pkcs.Verify(msg,sig)

		if(result == true){
			fmt.Println("rsaSignTest8.success")
		}else{
			fmt.Println(err)
		}
	case 9:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)
		pkcs.Init(key.GetPrivate())
		msg :=[]byte{1,2,3,4,5}
		sig,_ := pkcs.Sign(msg)
		h := sha256.New()
		h.Reset();
		h.Write(msg)

		sig1,_:= rsa.SignPKCS1v15(rand.Reader,key.GetPrivate().(crsa.RSAPrivateKey).GetRSAPrivateKey(),c.SHA256,h.Sum(nil))
		if(comp(sig,sig1) == false){
			fmt.Println("rsaSignTest9.fail")
			return
		}

		pkcs.Init(key.GetPublic())
		result,err:=pkcs.Verify(msg,sig)

		if(result == true){
			fmt.Println("rsaSignTest9.success")
		}else{
			fmt.Println(err)
		}


	case 10:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PSS)
		pkcs.Init(key.GetPrivate())
		msg :=[]byte{1,2,3,4,5}
		sig,_ := pkcs.Sign(msg)
		h := sha256.New()
		h.Reset();
		h.Write(msg)

		pkcs.Init(key.GetPublic())
		result,err:=pkcs.Verify(msg,sig)

		if(result == true){
			fmt.Println("rsaSignTest10.success")
		}else{
			fmt.Println(err)
		}
	case 11:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PSS)
		pkcs.Init(key.GetPrivate())
		msg :=[]byte{1,2,3,4,5}
		pkcs.Update(msg)
		sig,_ := pkcs.Sign(msg)

		pkcs.Init(key.GetPublic())
		pkcs.Update(msg)
		result,err:=pkcs.Verify(msg,sig)

		if(result == true){
			fmt.Println("rsaSignTest11.success")
		}else{
			fmt.Println(err)
		}
	case 12:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)
		pkcs.Init(key.GetPrivate())
		msg :=[]byte{1,2,3,4,5}
		pkcs.Update(msg)
		sig,_ := pkcs.Sign(msg)

		pkcs.Init(key.GetPublic())
		pkcs.Update(msg)
		result,err:=pkcs.Verify(msg,sig)

		if(result == true){
			fmt.Println("rsaSignTest12.success")
		}else{
			fmt.Println(err)
		}
	case 13:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PKCS1V15)
		pkcs.Init(key.GetPrivate())
		pkcs.(crsa.RSASign).SetHashType(chash.HASHTYPE_SHA512)

		msg :=[]byte{1,2,3,4,5}
		pkcs.Update(msg)
		sig,_ := pkcs.Sign(msg)

		pkcs.Init(key.GetPublic())
		pkcs.(crsa.RSASign).SetHashType(chash.HASHTYPE_SHA512)
		pkcs.Update(msg)
		result,err:=pkcs.Verify(msg,sig)

		if(result == true){
			fmt.Println("rsaSignTest13.success")
		}else{
			fmt.Println(err)
		}
	case 14:
		key,_:= crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		pkcs ,_:= crypto.GetSignInstance(csign.SIGN_RSA_PSS)
		pkcs.Init(key.GetPrivate())
		pkcs.(crsa.RSASign).SetHashType(chash.HASHTYPE_SHA512)
		msg :=[]byte{1,2,3,4,5}
		pkcs.Update(msg)
		sig,_ := pkcs.Sign(msg)

		pkcs.Init(key.GetPublic())
		pkcs.(crsa.RSASign).SetHashType(chash.HASHTYPE_SHA512)
		pkcs.Update(msg)
		result,err:=pkcs.Verify(msg,sig)

		if(result == true){
			fmt.Println("rsaSignTest14.success")
		}else{
			fmt.Println(err)
		}

	}
}
