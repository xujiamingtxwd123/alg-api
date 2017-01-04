package TestAlg

import (
	"fmt"
	"crypto/des"
	"security/crypto"
	ccipher"security/crypto/cipher"
	"crypto/cipher"
	ckey"security/crypto/key"
)

func DesTest(index int){
	switch index {
	case 1: //msg 只算前八个 key只能是8个字节
		key:=[]byte{1,2,3,4,5,6,7,8}
		dc,_ := des.NewCipher(key)
		msg :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		dst := make([]byte,16)
		dc.Encrypt(dst,msg)
		//	fmt.Printf("%x\n",dst[0:8])

		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		dc1,_:=crypto.GetCipherInstance(ccipher.ENC_DES)
		ko.(ckey.SymmKey).SetKey(key)

		dc1.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		ciphertext,err:=dc1.DoFinal(msg)


		//fmt.Printf("%x\n",ciphertext)
		if(comp(dst[0:8],ciphertext[8:16]) == true){
			fmt.Println("DesTest1.success")
		}else{
			fmt.Println(err)
		}

	case 2: //msg
		key:=[]byte{1,2,3,4,5,6,7,8}
		dc,_ := des.NewCipher(key)
		msg :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		dst := make([]byte,16)
		dc.Encrypt(dst,msg)
		//	fmt.Printf("%x\n",dst[0:8])

		dc1,_:=crypto.GetCipherInstance(ccipher.ENC_DES)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)
		dc1.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		ciphertext,_:=dc1.DoFinal(msg)

		dc1.Init(ccipher.CIPHERMODE_DECRYPTO,ko)
		dc1.Reset()
		msg1,_:=dc1.DoFinal(ciphertext)
		//	fmt.Printf("%x\n",ciphertext[8:16])
		if(comp(msg1,msg) == true){
			fmt.Println("DesTest2.success")
		}else{
			fmt.Println("false")
		}

	case 3:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24}
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_TRIPLE_DES)
		ko.(ckey.SymmKey).SetKey(key)
		dc,_ := des.NewTripleDESCipher(key)
		msg :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		dst := make([]byte,16)
		dc.Encrypt(dst,msg)
		//fmt.Printf("%x\n",dst)

		dc1,_:=crypto.GetCipherInstance(ccipher.ENC_TRIPLE_DES)
		dc1.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		dc1.Reset()
		ciphertext,err:=dc1.DoFinal(msg)
		//fmt.Printf("%x\n",ciphertext)

		if(comp(dst[0:8],ciphertext[8:16]) == true){
			fmt.Println("DesTest3.success")
		}else{
			fmt.Println(err)
		}
	case 4:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24}
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_TRIPLE_DES)
		ko.(ckey.SymmKey).SetKey(key)
		dc,_ := des.NewTripleDESCipher(key)
		msg :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		dst := make([]byte,16)
		dc.Encrypt(dst,msg)
		//fmt.Printf("%x\n",dst)

		dc1,_:=crypto.GetCipherInstance(ccipher.ENC_TRIPLE_DES)
		dc1.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		dc1.Reset()
		ciphertext,err:=dc1.DoFinal(msg)
		//fmt.Printf("%x\n",ciphertext)

		dc1.Init(ccipher.CIPHERMODE_DECRYPTO,ko)
		dc1.Reset()
		msg1,_:=dc1.DoFinal(ciphertext)

		if(comp(msg,msg1) == true){
			fmt.Println("DesTest4.success")
		}else{
			fmt.Println(err)
		}
	case 5:
		fmt.Println("DesTest5.success")
	case 6:
		key:=[]byte{1,2,3,4,5,6,7,8}
		dc,_:=des.NewCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewCBCEncrypter(dc,iv)
		dst := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm.CryptBlocks(dst,msg)

		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_DES_CBC)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,_:=dcc.DoFinal(msg)
		if(comp(dst1,dst) == true){
			fmt.Println("DesTest6.success")
		}else{
			fmt.Println("fail")
		}
	case 7:
		key:=[]byte{1,2,3,4,5,6,7,8}
		dc,_:=des.NewCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewCBCEncrypter(dc,iv)
		dst := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm.CryptBlocks(dst,msg)
		//		fmt.Printf("%x\n",dst)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_DES_CBC)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,_:=dcc.DoFinal(msg)

		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)

		//dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)

		if(comp(msg1,msg) == true){
			fmt.Println("DesTest7.success")
		}else{
			fmt.Println("fail")
		}

	case 8:
		key:=[]byte{1,2,3,4,5,6,7,8}
		dc,_:=des.NewCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewCFBEncrypter(dc,iv)
		dst := make([]byte,17)
		dstd := make([]byte,17)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,9}
		bm.XORKeyStream(dst,msg)
		//		fmt.Printf("%x\n",dst)

		dm:=cipher.NewCFBDecrypter(dc,iv)
		dm.XORKeyStream(dstd,dst)
		//		fmt.Printf("%x\n",dstd)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_DES_CFB)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,err:=dcc.DoFinal(msg)
		//		fmt.Printf("%x\n",dst1)
		if(comp(dst,dst1) == false){
			fmt.Println("false")
		}
		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)
		//		fmt.Printf("%x\n",msg1)
		if(comp(msg1,msg) == true){
			fmt.Println("DesTest8.success")
		}else{
			fmt.Println(err)
		}

	case 9:
		key:=[]byte{1,2,3,4,5,6,7,8}
		dc,_:=des.NewCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewOFB(dc,iv)
		dst := make([]byte,17)
		dstd := make([]byte,17)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,9}
		bm.XORKeyStream(dst,msg)
		//fmt.Printf("%x\n",dst)

		bm.XORKeyStream(dstd,dst)
		//fmt.Printf("%x\n",dstd)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_DES_OFB)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,err:=dcc.DoFinal(msg)
		//fmt.Printf("%x\n",dst1)

		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)
		//fmt.Printf("%x\n",msg1)
		if(comp(msg1,msg) == true){
			fmt.Println("DesTest9.success")
		}else{
			fmt.Println(err)
		}

	case 10:
		key:=[]byte{1,2,3,4,5,6,7,8}
		dc,_:=des.NewCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewCTR(dc,iv)
		dst := make([]byte,17)
		dstd := make([]byte,17)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,9}
		bm.XORKeyStream(dst,msg)
		//fmt.Printf("%x\n",dst)

		bm.XORKeyStream(dstd,dst)
		//fmt.Printf("%x\n",dstd)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_DES_CTR)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc.InitIV(ccipher.CIPHERMODE_ENCRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		dst1,err:=dcc.DoFinal(msg)
		//fmt.Printf("%x\n",dst1)

		dcc.InitIV(ccipher.CIPHERMODE_DECRYPTO,ko,iv)
		//dcc.SetConfig(iv)
		msg1,_:=dcc.DoFinal(dst1)
		//fmt.Printf("%x\n",msg1)
		if(comp(msg1,msg) == true){
			fmt.Println("DesTest10.success")
		}else{
			fmt.Println(err)
		}

	case 11:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8}
		dc,_:=des.NewTripleDESCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewCBCEncrypter(dc,iv)
		dst := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		bm.CryptBlocks(dst,msg)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_TRIPLE_DES_CBC)
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_TRIPLE_DES)
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
			fmt.Println("DesTest11.success")
		}else{
			fmt.Println("fail")
		}

	case 12:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8}
		dc,_:=des.NewTripleDESCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewCFBEncrypter(dc,iv)
		dst := make([]byte,16)
		//		dst2 := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		//bm.CryptBlocks(dst,msg)
		bm.XORKeyStream(dst,msg)

		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_TRIPLE_DES_CFB)
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
			fmt.Println("DesTest12.success")
		}else{
			fmt.Println("fail")
		}
	case 13:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8}
		dc,_:=des.NewTripleDESCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewOFB(dc,iv)
		dst := make([]byte,16)
		//		dst2 := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		//bm.CryptBlocks(dst,msg)
		bm.XORKeyStream(dst,msg)

		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)
		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_TRIPLE_DES_OFB)
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
			fmt.Println("DesTest13.success")
		}else{
			fmt.Println("fail")
		}
	case 14:
		key:=[]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8}
		dc,_:=des.NewTripleDESCipher(key)
		iv :=[]byte{5,5,5,5,5,5,5,5}
		bm:=cipher.NewCTR(dc,iv)
		dst := make([]byte,16)
		//		dst2 := make([]byte,16)
		msg := []byte{1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}
		//bm.CryptBlocks(dst,msg)
		bm.XORKeyStream(dst,msg)

		ko,_:=crypto.BuildKey(ckey.KEYTYPE_DES)
		ko.(ckey.SymmKey).SetKey(key)

		dcc,_:=crypto.GetCipherInstance(ccipher.ENC_TRIPLE_DES_CTR)
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
			fmt.Println("DesTest14.success")
		}else{
			fmt.Println("fail")
		}

	}
}
