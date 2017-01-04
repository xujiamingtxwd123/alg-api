package TestAlg

import(
	"fmt"
	ckey"security/crypto/key"
	"security/crypto"
	csign"security/crypto/sign"
	xed"golang.org/x/crypto/ed25519"
	ced25519"security/crypto/ed25519"
	"crypto/rand"
)


func ED25519SignTest(index int){
	switch index {
	case 1:
		key,_:=crypto.KeyPair(ckey.KEYPAIRTYPE_ED25519,ckey.KEYLENGTH_ED25519)
		ed,_:=crypto.GetSignInstance(csign.SIGN_ED25519)
		ed.Init(key.GetPrivate())
		msg:=[]byte{1,2,3,4,5,6,7,8,9}
		dst,_ := ed.Sign(msg)
		ed.Init(key.GetPublic())
		result,_:=ed.Verify(msg,dst)

		if(result == true){
			fmt.Println("ed25519Test1.success")
		}else{
			fmt.Println("false")
		}

	case 2:

		key,_:=crypto.KeyPair(ckey.KEYPAIRTYPE_ED25519,ckey.KEYLENGTH_ED25519)
		ed,_:=crypto.GetSignInstance(csign.SIGN_ED25519)
		ed.Init(key.GetPrivate())
		msg:=[]byte{1,2,3,4,5,6,7,8,9}
		dst,_ := ed.Sign(msg)

		dst1:=xed.Sign((key.GetPrivate().(ced25519.ED25519PrivateKey).GetED25519PrivateKey()),msg)


		if(comp(dst,dst1) == false){
			fmt.Println("false")
		}else{
			fmt.Println("ed25519Test2.success")
		}
	case 3:
		//key,_:=crypto.KeyPair(ckey.KEYPAIRTYPE_ED25519,ckey.KEYLENGTH_ED25519)
		k1,k2,_:=xed.GenerateKey(rand.Reader)
		key,_:=crypto.BuildKey(ckey.KEYTYPE_ED25519_PRIVATE)
		key.(ced25519.ED25519PrivateKey).SetED25519PrivateKey(k2)
		ed,_:=crypto.GetSignInstance(csign.SIGN_ED25519)
		ed.Init(key)
		msg:=[]byte{1,2,3,4,5,6,7,8,9}
		dst,_ := ed.Sign(msg)
		key1,_:=crypto.BuildKey(ckey.KEYTYPE_ED25519_PUBLIC)
		key1.(ced25519.ED25519PublicKey).SetED25519PublicKey(k1)


		ed.Init(key1)
		result,_:=ed.Verify(msg,dst)

		if(result == true){
			fmt.Println("ed25519Test3.success")
		}else{
			fmt.Println("false")
		}


	}
}
