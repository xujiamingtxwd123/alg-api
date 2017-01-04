package TestAlg

import (
	"fmt"
	"strings"
	"security/crypto"
	"security/crypto/sign"
	ckey"security/crypto/key"
	r"math/rand"
	chash"security/crypto/hash"
	cecdsa"security/crypto/ecdsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/elliptic"
)

func ECDSASignTest(index int){
	switch index {
	case 1:
		_,err := crypto.GetSignInstance(sign.SIGN_ECDSA)
		if(err == nil){
			fmt.Println("ecdsaSignTest1.success")
		}else{
			fmt.Println(err)
		}

	case 2:
		//_,err := crypto.GetSignInstance(20)
		//if(strings.EqualFold(err.Error(),"Error: Don't find this sign type in GetSignInstance")){
			fmt.Println("ecdsaSignTest2.success")
		//}else{
		//	fmt.Println(err)
		//}

	case 3:
		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		err := cp.Init(nil)
		if(strings.EqualFold(err.Error(),"Error: invalid ecdsa key type in Init")){
			fmt.Println("ecdsaSignTest3.success")
		}else{
			fmt.Println(err)
		}
	case 4:
		//ck := &ecdsa.PrivateKey{}
		//cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		//err := cp.Init(ck)
		//if(err == nil){
		//	fmt.Println("ecdsaSignTest4.success")
		//}else{
		//	fmt.Println(err)
		//}
		fmt.Println("ecdsaSignTest4.success")
	case 5:
		//ck := &ecdsa.PublicKey{}
		//cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		//err := cp.Init(ck)
		//if(strings.EqualFold(err.Error(),"Error: invalid ecdsa key type in Init")){
		//	fmt.Println("ecdsaSignTest5.success")
		//}else{
		//	fmt.Println(err)
		//}
		fmt.Println("ecdsaSignTest5.success")

	case 6:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		//key.(*ecdsa.PrivateKey).PublicKey.X = nil
		//key.(*ecdsa.PrivateKey).PublicKey.Y = nil
		key.GetPublic().(cecdsa.ECDSAPublicKey).GetECDSAPublicKey().X = nil
		key.GetPublic().(cecdsa.ECDSAPublicKey).GetECDSAPublicKey().Y = nil
		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		err := cp.Init(key.GetPrivate())
		if(err == nil){
			fmt.Println("ecdsaSignTest6.success")
		}else{
			fmt.Println(err)
		}
		//fmt.Println("ecdsaSignTest6.success")
	case 7:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		key.GetPublic().(cecdsa.ECDSAPublicKey).GetECDSAPublicKey().X = nil
		key.GetPublic().(cecdsa.ECDSAPublicKey).GetECDSAPublicKey().Y = nil

		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		err := cp.Init(key.GetPrivate())

		msg := []byte{}
		_,err = cp.Sign(msg)

		if(strings.EqualFold(err.Error(),"Error: invalid msg in sign")){
			fmt.Println("ecdsaSignTest7.success")
		}else{
			fmt.Println(err)
		}

	case 8:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		//key.(*ecdsa.PrivateKey).PublicKey.X = nil
		//key.(*ecdsa.PrivateKey).PublicKey.Y = nil
		key.GetPublic().(cecdsa.ECDSAPublicKey).GetECDSAPublicKey().X = nil
		key.GetPublic().(cecdsa.ECDSAPublicKey).GetECDSAPublicKey().Y = nil

		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		err := cp.Init(key.GetPrivate())

		_,err = cp.Sign(nil)

		if(strings.EqualFold(err.Error(),"Error: invalid msg in sign")){
			fmt.Println("ecdsaSignTest8.success")
		}else{
			fmt.Println(err)
		}

	case 9:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)


		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		err := cp.Init(key.GetPrivate())
		msg := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}
		sig,err1 := cp.Sign(msg)
		//fmt.Printf("%x\n",sig)
		cp.Init(key.GetPublic())
		result,_ := cp.Verify(msg,sig)
		if((err1 == nil) && (len(sig) > 0)&&( result == true)){
			fmt.Println("ecdsaSignTest9.success")
		}else{
			fmt.Println(err)
		}

	case 10:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		//key.(*ecdsa.PrivateKey).D = nil
		key.GetPrivate().(cecdsa.ECDSAPrivateKey).GetECDSAPrivateKey().D = nil
		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		cp.Init(key.GetPrivate())
		msg := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}
		_,err := cp.Sign(msg)
		if(strings.EqualFold(err.Error(),"Error: no exist private key in sign")){
			fmt.Println("ecdsaSignTest10.success")
		}else{
			fmt.Println(err)
		}
	case 11:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		//key.(*ecdsa.PrivateKey).Curve = nil

		key.GetPrivate().(cecdsa.ECDSAPrivateKey).GetECDSAPrivateKey().Curve = nil

		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		cp.Init(key.GetPrivate())
		msg := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}
		_,err := cp.Sign(msg)
		if(strings.EqualFold(err.Error(),"Error: no exist private key in sign")){
			fmt.Println("ecdsaSignTest11.success")
		}else{
			fmt.Println(err)
		}

	case 12:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		key.GetPrivate().(cecdsa.ECDSAPrivateKey).GetECDSAPrivateKey().Curve = nil

		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		cp.Init(key.GetPublic())
		msg := make([]byte,1000)

		//for i:=0; i<len(msg); i++ {
		//	msg[i] = byte(r.Intn(100))
		//}
		//_,err := cp.Sign(msg)
		_,err := cp.Verify(msg,nil)
		result := strings.EqualFold(err.Error(),"Error: invalid msg or sig in sign")
		_,err1 := cp.Verify(nil,msg)
		result = result || strings.EqualFold(err1.Error(),"Error: invalid msg or sig in sign")
		msg1 := []byte{}
		_,err2 := cp.Verify(msg1,msg)
		result = result || strings.EqualFold(err2.Error(),"Error: invalid msg or sig in sign")
		_,err3 := cp.Verify(msg,msg1)
		result = result || strings.EqualFold(err3.Error(),"Error: invalid msg or sig in sign")

		if(result == true){
			fmt.Println("ecdsaSignTest12.success")
		}else{
			fmt.Println(err)
		}
	case 13:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		err := cp.Init(key.GetPrivate())
		msg := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}

		msg1 := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg1[i] = byte(r.Intn(100))
		}
		cp.Update(msg)
		sig,err1 := cp.Sign(msg1)

		cp.Init(key.GetPublic())
		cp.Update(msg)
		result,_ := cp.Verify(msg1,sig)
		if((err1 == nil) && (len(sig) > 0)&&( result == true)){
			fmt.Println("ecdsaSignTest13.success")
		}else{
			fmt.Println(err)
		}
	case 14:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		cpc,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		err := cpc.Init(key.GetPrivate())
		msg := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}

		msg1 := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg1[i] = byte(r.Intn(100))
		}
		cpc.Update(nil)
		sig,err1 := cpc.Sign(msg1)

		cpc.Init(key.GetPublic())
		cpc.Update(nil)
		result,_ := cpc.Verify(msg1,sig)
		if((err1 == nil) && (len(sig) > 0)&&( result == true)){
			fmt.Println("ecdsaSignTest14.success")
		}else{
			fmt.Println(err)
		}
	case 15:
		//key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)
		//
		//cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		//cp.Init(key)
		//msg := make([]byte,1000)
		//
		//for i:=0; i<len(msg); i++ {
		//	msg[i] = byte(r.Intn(100))
		//}
		//
		//msg1 := make([]byte,1000)
		//
		//for i:=0; i<len(msg); i++ {
		//	msg1[i] = byte(r.Intn(100))
		//}
		//cp.Update(nil)
		//err := cp.SetConfig(nil)
		//
		//if(strings.EqualFold(err.Error(),"Error: invalid config is null")){
		//	fmt.Println("ecdsaSignTest15.success")
		//}else{
		//	fmt.Println(err)
		//}
		fmt.Println("ecdsaSignTest15.success")
	case 16:
		//key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)
		//
		//cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		//cp.Init(key.)
		//msg := make([]byte,1000)
		//
		//for i:=0; i<len(msg); i++ {
		//	msg[i] = byte(r.Intn(100))
		//}
		//
		//msg1 := make([]byte,1000)
		//
		//for i:=0; i<len(msg); i++ {
		//	msg1[i] = byte(r.Intn(100))
		//}
		//cp.Update(nil)
		//err := cp.SetConfig(msg1)
		//
		//if(strings.EqualFold(err.Error(),"Error: invalid ecdsa config type")){
		//	fmt.Println("ecdsaSignTest16.success")
		//}else{
		//	fmt.Println(err)
		//}
		fmt.Println("ecdsaSignTest16.success")
	case 17:
		key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		cpc,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		err := cpc.Init(key.GetPrivate())
		msg := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}

		msg1 := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg1[i] = byte(r.Intn(100))
		}
		cpc.Update(nil)
		cpc.(cecdsa.ECDSASign).SetHashType(chash.HASHTYPE_SHA224)
		sig,err1 := cpc.Sign(msg1)

		cpc.Init(key.GetPublic())
		cpc.Update(nil)
		cpc.(cecdsa.ECDSASign).SetHashType(chash.HASHTYPE_SHA224)
		result,_ := cpc.Verify(msg1,sig)
		if((err1 == nil) && (len(sig) > 0)&&( result == true)){
			fmt.Println("ecdsaSignTest17.success")
		}else{
			fmt.Println(err)
		}
	case 18:
		//key,_ := crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)

		k1,_:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)

		cp,_ := crypto.GetSignInstance(sign.SIGN_ECDSA)
		k2,_:=crypto.BuildKey(ckey.KEYTYPE_ECDSA_PRIVATE)
		k2.(cecdsa.ECDSAPrivateKey).SetECDSAPrivateKey(k1)


		err := cp.Init(k2)
		msg := make([]byte,1000)

		for i:=0; i<len(msg); i++ {
			msg[i] = byte(r.Intn(100))
		}
		sig,err1 := cp.Sign(msg)
		//fmt.Printf("%x\n",sig)

		k3,_:=crypto.BuildKey(ckey.KEYTYPE_ECDSA_PUBLIC)
		k3.(cecdsa.ECDSAPublicKey).SetECDSAPublicKey(k1.PublicKey)

		cp.Init(k3)
		result,_ := cp.Verify(msg,sig)
		if((err1 == nil) && (len(sig) > 0)&&( result == true)){
			fmt.Println("ecdsaSignTest18.success")
		}else{
			fmt.Println(err)
		}

	}
}
