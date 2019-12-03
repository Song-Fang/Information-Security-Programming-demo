package com.SongFangProject;
import java.io.*;
import java.net.*;
import java.security.*;

import javax.xml.bind.DatatypeConverter;

import java.math.BigInteger;

public class ElGamalBob
{
	private static boolean verifySignature(	BigInteger y, BigInteger g, BigInteger p, BigInteger a, BigInteger b, String message)
	{
		// IMPLEMENT THIS FUNCTION;
		String cypherMessage=encryption(message);
		BigInteger msg_hash=new BigInteger(cypherMessage.getBytes());
		BigInteger left=g.modPow(msg_hash,p);
		BigInteger t1=y.modPow(a, p);
		BigInteger t2=a.modPow(b, p);
		BigInteger t3=t1.multiply(t2);
		BigInteger right=t3.mod(p);
		if(left.equals(right)){
			return true;
		}
		return false;
	}
	
	

	public static void main(String[] args) throws Exception 
	{
		int port = 7999;
		ServerSocket s = new ServerSocket(port);
		Socket client = s.accept();
		ObjectInputStream is = new ObjectInputStream(client.getInputStream());

		// read public key
		BigInteger y = (BigInteger)is.readObject();
		BigInteger g = (BigInteger)is.readObject();
		BigInteger p = (BigInteger)is.readObject();

		// read message
		String message = (String)is.readObject();

		// read signature
		BigInteger a = (BigInteger)is.readObject();
		BigInteger b = (BigInteger)is.readObject();

		boolean result = verifySignature(y, g, p, a, b, message);

		System.out.println(message);

		if (result == true)
			System.out.println("Signature verified.");
		else
			System.out.println("Signature verification failed.");

		s.close();
	}
	
	public static String encryption(String str){
		try{
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte buf[] = str.getBytes();
			md.update(buf);
			byte digest[]=md.digest();
			String Md5_message= DatatypeConverter.printHexBinary(digest).toUpperCase();
			//System.out.println("The MyMessageDigest message is: "+ Md5_message);
			return Md5_message;
		}catch(NoSuchAlgorithmException e){
			e.printStackTrace();
			return null;
		}
	}
}