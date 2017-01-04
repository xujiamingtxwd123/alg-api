package TestAlg

import "security/crypto"
import ckey"security/crypto/key"
import cblind"security/crypto/rsa_blind"
import (
	"crypto/rand"
	"fmt"
)

func BlindTest(index int){

	switch index {
	case 1:
		//key,_:=crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		dstkey,_:=crypto.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		//key.GetPublic()
		//pubkey ,_:=crypto.BuildKey(ckey.KEYTYPE_RSA_PUBLIC)
		msg := make([]byte, 100)
		rand.Read(msg)
		c,r,err:=cblind.Blind(dstkey.GetPublic(),msg)
		if(err != nil){
			fmt.Println("Blind:%s",err)
		}
		sig,err:=cblind.BlindSign(dstkey.GetPrivate(),c)
		if(err != nil){
			fmt.Println("BlindSign:%s",err)
		}
		sigorc,err:=cblind.Unblind(dstkey.GetPublic(),sig,r)
		if(err != nil){
			fmt.Println("Unblind:%s",err)
		}
		result,err:=cblind.VerifySignature(dstkey.GetPublic(),c,sig)
		if(err != nil){
			fmt.Println("VerifyBlindSignature:%s",err)
		}
		if(result == true){
			fmt.Println("BlindTest0.success")
			return
		}else{
			fmt.Println("BlindTest0.fail")
			return
		}

		result,err =cblind.VerifyBlindSignature(dstkey.GetPublic(),msg,sigorc)
		if(err != nil){
			fmt.Println("VerifyBlindSignature:%s",err)
		}
		if(result == true){
			fmt.Println("BlindTest0.success")
			return
		}else{
			fmt.Println("BlindTest0.fail")
			return
		}


	}

}
