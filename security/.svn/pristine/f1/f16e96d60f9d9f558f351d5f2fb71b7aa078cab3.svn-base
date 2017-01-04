package TestAlg

import (
	"fmt"
	"strings"
	"crypto/aes"
	"security/crypto"
	ccipher"security/crypto/cipher"
	ckey"security/crypto/key"
	"crypto/cipher"
	r"math/rand"
	//"security/crypto/gcm"
	cgcm"security/crypto/gcm"
)

func AesTest(index int){
	switch index {
	case 1:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc1,_:=crypto.GetCipherInstance(ccipher.ENC_AES)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dc1.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		msg:= make([]byte,100)
		_,err:=dc1.DoFinal(msg)
		if(strings.EqualFold(err.Error(),"invalid msg length")){
			fmt.Println("AesTest1.success")
		}else{
			fmt.Println(err)
		}

	case 2:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc1,_:=crypto.GetCipherInstance(ccipher.ENC_AES)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dc1.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		msg:= make([]byte,128)
		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}
		dst,err:=dc1.DoFinal(msg)

		dc,_ := aes.NewCipher(key)
		dst1 := make([]byte,16)
		dc.Encrypt(dst1,msg[16:32])


		if(comp(dst1,dst[16:32]) == true){
			fmt.Println("AesTest2.success")
		}else{
			fmt.Println(err)
		}
	case 3:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc,_:=aes.NewCipher(key)
		iv :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm:=cipher.NewCBCEncrypter(dc,iv)
		dst := make([]byte,16)
		msg := []byte{2,2,2,2,2,3,3,3,3,3,4,4,4,4,4,5}
		bm.CryptBlocks(dst,msg)
		//		fmt.Printf("%x\n",dst)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_AES_CBC)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,_:=dcc.DoFinal(msg)
		if(comp(dst1,dst) == true){
			fmt.Println("AesTest3.success")
		}else{
			fmt.Println("fail")
		}
	case 4:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc,_:=aes.NewCipher(key)
		iv :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm:=cipher.NewCBCEncrypter(dc,iv)
		dst := make([]byte,16)
		msg := []byte{2,2,2,2,2,3,3,3,3,3,4,4,4,4,4,5}
		bm.CryptBlocks(dst,msg)
		//		fmt.Printf("%x\n",dst)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_AES_CBC)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,_:=dcc.DoFinal(msg)

		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)

		if(comp(msg1,msg) == true){
			fmt.Println("AesTest4.success")
		}else{
			fmt.Println("fail")
		}

	case 5:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc,_:=aes.NewCipher(key)
		//iv :=[]byte{5,5,5,5,5,5,5,5}
		bm,_:=cipher.NewGCM(dc)
		//dst := make([]byte,17)
		//dstd := make([]byte,17)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,9,10}
		nonce := []byte{1,2,3,4,5,6,7,8,9,10,11,12}
		dst:=bm.Seal(nil,nonce,msg,nil)
		//fmt.Printf("%x\n",dst)
		//dst=bm.Seal(nil,nonce,msg,nil)
		//fmt.Printf("%x\n",dst)
		dstd,_:=bm.Open(nil,nonce,dst,nil)
		//fmt.Printf("%x\n",dstd)

		if(comp(dstd,msg) == true){
			fmt.Println("AesTest5.success")
		}else{
			fmt.Println("fail")
		}

	case 6:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc,_:=aes.NewCipher(key)
		iv :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm:=cipher.NewCBCEncrypter(dc,iv)
		dst := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm.CryptBlocks(dst,msg)
		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_AES_CBC)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,_:=dcc.DoFinal(msg)
		//
		if(comp(dst,dst1) == false){
			fmt.Println("fail")
		}

		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)

		if(comp(msg1,msg) == true){
			fmt.Println("DesTest6.success")
		}else{
			fmt.Println("fail")
		}

	case 7:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc,_:=aes.NewCipher(key)
		iv :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm:=cipher.NewCFBEncrypter(dc,iv)
		dst := make([]byte,16)
		//		dst2 := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		//bm.CryptBlocks(dst,msg)
		bm.XORKeyStream(dst,msg)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_AES_CFB)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
	//	dcc.SetConfig(iv)
		dst1,_:=dcc.DoFinal(msg)
		//
		if(comp(dst,dst1) == false){
			fmt.Println("fail")
		}

		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)

		if(comp(msg1,msg) == true){
			fmt.Println("DesTest7.success")
		}else{
			fmt.Println("fail")
		}
	case 8:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc,_:=aes.NewCipher(key)
		iv :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm:=cipher.NewOFB(dc,iv)
		dst := make([]byte,16)
		//		dst2 := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		//bm.CryptBlocks(dst,msg)
		bm.XORKeyStream(dst,msg)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_AES_OFB)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,_:=dcc.DoFinal(msg)
		//
		if(comp(dst,dst1) == false){
			fmt.Println("fail")
		}

		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)

		if(comp(msg1,msg) == true){
			fmt.Println("DesTest8.success")
		}else{
			fmt.Println("fail")
		}
	case 9:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc,_:=aes.NewCipher(key)
		iv :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm:=cipher.NewCTR(dc,iv)
		dst := make([]byte,16)

		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		//bm.CryptBlocks(dst,msg)
		bm.XORKeyStream(dst,msg)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_AES_CTR)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,_:=dcc.DoFinal(msg)
		//
		if(comp(dst,dst1) == false){
			fmt.Println("fail")
		}

		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)
	//	dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)

		if(comp(msg1,msg) == true){
			fmt.Println("DesTest9.success")
		}else{
			fmt.Println("fail")
		}
	case 10:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
		dc,_:=aes.NewCipher(key)
		bm,_:=cipher.NewGCM(dc)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		nonce := []byte{1,2,3,4,5,6,7,8,9,10,11,12}
		dst:=bm.Seal(nil,nonce,msg,nil)


		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_AES_GCM)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_AES)
		//ko,_:=ckey.BuildKey(ckey.KEYTYPE_AES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		dcc.(cgcm.GCMCipher).SetAdditional(nil)
		dcc.(cgcm.GCMCipher).SetNonce(nonce)
		//dcc.SetConfig(gcm.Conf{nonce,nil})
		dst1,_:=dcc.DoFinal(msg)
		//
		if(comp(dst,dst1) == false){
			fmt.Println("fail")
		}

		dcc.Init(ccipher.CIPHERMODE_DECRYPTO,ko)
		dcc.(cgcm.GCMCipher).SetAdditional(nil)
		dcc.(cgcm.GCMCipher).SetNonce(nonce)
		//dcc.SetConfig(&gcm.Conf{nonce,nil})
		msg1,_:=dcc.DoFinal(dst1)

		if(comp(msg1,msg) == true){
			fmt.Println("DesTest10.success")
		}else{
			fmt.Println("fail")
		}




	}
}


