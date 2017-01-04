package main

import st"security/TestAlg"

/*

//定义多层interface 减少变量中interface出现
//定义统一的key封装类型
//CIPHERMODE_ENCRYPTO_DECRYPTO//去掉
//使用延迟加载 用时发现为空才new
//Clear -> Reset


理解  b := aa{}这种赋值 生成的aa地址等于当前b的地址，不过go语言不提供&b来获取b的地址
只要有&操作的赋值都是指针  b:= &aa{} 表示b是指针，指向aa的地址
对于成员函数 不根据调用处的类型，根据的是成员函数是用指针修饰 还是非指针修饰（a *aa）fuck()，如果函数是指针修饰，那外面是指针就复制指针，外面是结构体就复制结构体
函数返回值如果不是指针则也要全复制
这里还要提醒一句,对于[goroutin(程道)],[切片],[映射]这三种类型来说,只有形参,而且不需要加[*]号.
另外,对于参数类型是[interface]的函数参数,只有实参,而且不会将[interface]结构所包含的地址复制!
成员函数如果使用指针修饰（a *aa）fuck  ，调用时不会理会是否是用指针调用。不过如果是如参是指针，传入不是地址则直接报错
指针给指针赋值
a := &&aa{}   var b *aa    b := a   b是指向谁的地址
需要测试 多级指针赋值


关于密钥长度的判断没有做todo
关于密钥导出的方案和测试
关于调用的权限
非法key的检查


*/
func main(){


	for i:= 1; i< 5;i++{
		st.RsaKeyTest(i)
	}

	for i:= 1; i< 6;i++{
		st.EcdsaKeyTest(i)
	}

	for i:= 1; i< 5;i++{
		st.RsaEncTest(i)
	}

	for i:= 1; i< 15;i++{
		st.RsaSignTest(i)
	}
	for i:= 1; i< 19;i++{
		st.ECDSASignTest(i)
	}

	for i:= 1; i< 4;i++{
		st.ED25519SignTest(i)
	}

	for i:= 1; i< 2;i++{
		st.RC4EncTest(i)
	}

	for i:= 1; i< 15;i++{
		st.DesTest(i)
	}

	for i:= 1; i< 11;i++{
		st.AesTest(i)
	}

	for i:= 1; i< 2;i++{
		st.HMACTest(i)
	}

	for i:=1;i<4;i++{
		st.KeyImportExport(i)
	}

	for i:=1;i<2;i++{
		st.BlindTest(i)
	}
	for i:=1;i<2;i++{
		st.RingSignTest(i)
	}


}