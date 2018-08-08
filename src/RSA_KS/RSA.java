package RSA_KS;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class RSA {
	private static final int RANDOMNUM=1;	//每个分组添加的随机数个数
	private RSAWindow frame;
	private BigInteger p,q,n,f,e,d;
	
	//构造函数
	RSA(RSAWindow frame)
	{
		this.frame=frame;
	}
	//生成p,q,n
	protected void producePQN(int keyLength)
	{
//		while(true)
//		{
			Random rnd =new Random();
			p=BigInteger.probablePrime(keyLength/2, rnd);
			q=BigInteger.probablePrime(keyLength/2, rnd);
			n=p.multiply(q);
//			if(n.toByteArray()[0]>15) break;
//		}
		f=p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));//f=(p-1)*(q-1);
		//显示
		frame.JTFP.setText(p.toString(16));
		frame.JTFQ.setText(q.toString(16));
		frame.JTFN.setText(n.toString(16));
	}
	//生成e,d
	protected void produceED()
	{
		e=new BigInteger("65537");				//1<=e<f且e,f互素
		d=e.modPow(BigInteger.valueOf(-1), f);	//d等于e模f的逆元
		//显示
		frame.JTFE.setText(e.toString(16));
		frame.JTFD.setText(d.toString(16));
	}
	//=======================================加密===================================
	//加密
		protected static String encrypt(byte plainByte[],BigInteger n,BigInteger e)
		{
			BigInteger c;	//密文
			byte groupArr[]=new byte[plainByte.length+RANDOMNUM+1];	//待加密字节数组
			//开头添加0(保证m满位下,m<n并且方便给码字为负数的字符(比如中文)编码),添加随机数,保证安全性
			Random rnd =new Random();
			groupArr[0]=(byte)0;							//加上0
			for(int i=0;i<RANDOMNUM;i++)
			{
//				groupArr[i+1]=(byte)(100);
				groupArr[i+1]=(byte)(rnd.nextInt(50)+70);	//每个分组前加随机数
			}
			for(int i=0;i<plainByte.length;i++)
			{
				groupArr[i+RANDOMNUM+1]=plainByte[i];
			}
			
			BigInteger m=new BigInteger(groupArr);				//将明文字节数组转化为大整数
			c=m.modPow(e, n);									//c等于m的e次方模n
			return c.toString(16);
		}
	//分组
	protected void enDivide(String plain,BigInteger n,BigInteger e,int keyLength) throws UnsupportedEncodingException
	{
		int groupLength=keyLength/8;						//分组长度
		int plainGroupLength=groupLength-RANDOMNUM-1;		//明文分组长度
		byte plainByte[]=plain.getBytes("utf-8");			//得到字节数组(每个字符转化为一个字节编码)
		
		if(plainByte.length<=plainGroupLength)				//只有一个分组
		{
			//显示
			frame.JTAC.setText(encrypt(plainByte,n,e));
		}
		else
		{
			//分组
			byte subArr[]=new byte[plainGroupLength];	//明文分组的字节数组
			int i;										//i计数
			frame.JTAC.setText("");						//清空密文框
			for(i=0;i<plainByte.length/plainGroupLength;i++)
			{
				for(int j=0;j<plainGroupLength;j++)
				{
					subArr[j]=plainByte[i*plainGroupLength+j];
				}
				//显示
				frame.JTAC.append(encrypt(subArr,n,e));
			}
			int rest=plainByte.length%plainGroupLength;
			if(rest!=0)									//存在不足位数的组
			{
				subArr=new byte[rest];
				for(int j=0;j<rest;j++)
				{
					subArr[j]=plainByte[i*plainGroupLength+j];
				}
				//显示
				frame.JTAC.append(encrypt(subArr,n,e));
			}
		}
	}
	
	//============================================解密=======================================
	//解密
	protected static byte[] decrypt(String cipher,BigInteger n,BigInteger d)
	{
		BigInteger c=new BigInteger(cipher,16);		//将密文字符串(16进制的)转换为大整数
		BigInteger m=c.modPow(d, n);				//m=c的d次方模n
		byte groupArr[]=m.toByteArray();			//得到字节数组
		byte plainByte[]=new byte[groupArr.length-RANDOMNUM];
		for(int i=0;i<plainByte.length;i++)
		{
			plainByte[i]=groupArr[i+RANDOMNUM];		//去掉加入的随机数
		}
		return plainByte;
	}
	//分组
	protected void deDivide(String cipher,BigInteger n,BigInteger d,int keyLength) throws UnsupportedEncodingException
	{
		String plain;						//明文
		int groupLength=keyLength/4;		//每4位1个16进制数
		if(cipher.length()<=groupLength)	//仅有一个分组的情况
		{
			plain=new String(decrypt(cipher,n,d),"utf-8");	//将字节数组翻译为字符
			//显示
			frame.JTAM.setText(plain);
		}
		else
		{
			//分组
			String subStr;	//子串
			byte plainByte[];
			int i=0;
			//第一组
			subStr=cipher.substring(i*groupLength,(i+1)*groupLength);
			plainByte=decrypt(subStr,n,d);
			//剩余组
			for(i=1;i<cipher.length()/groupLength;i++)
			{
				subStr=cipher.substring(i*groupLength,(i+1)*groupLength);
				plainByte= concatArray(plainByte,decrypt(subStr,n,d));
			}
			if(cipher.length()%groupLength!=0)
			{
				subStr=cipher.substring(i*groupLength);
				plainByte= concatArray(plainByte,decrypt(subStr,n,d));
			}
			plain=new String(plainByte,"utf-8");
			frame.JTAM.setText(plain);
		}
	}
	//=================================工具==============================
	protected BigInteger getN()
	{
		return n;
	}
	protected BigInteger getE()
	{
		return e;
	}
	protected BigInteger getD()
	{
		return d;
	}
	//合并数组
	public static byte[] concatArray(byte[] first, byte[] second) 
	{  
		byte[] result = Arrays.copyOf(first, first.length + second.length);  
		System.arraycopy(second, 0, result, first.length, second.length);  
		return result;  
	}   
}
