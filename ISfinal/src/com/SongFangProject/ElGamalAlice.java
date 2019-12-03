package com.SongFangProject;
import java.io.*;
import java.net.*;
import java.security.*;

import javax.xml.bind.DatatypeConverter;

import java.math.BigInteger;

public class ElGamalAlice
{
	private static BigInteger computeY(BigInteger p, BigInteger g, BigInteger d)
	{
		// IMPLEMENT THIS FUNCTION;
		// y = g % pow(d,p)
		BigInteger y;
		y = g.modPow(d, p); 
		return y;
	}

	private static BigInteger computeK(BigInteger p)
	{
		// IMPLEMENT THIS FUNCTION;
		int mLens = p.bitLength()-1;
		BigInteger n;
		SecureRandom secureRandom = new SecureRandom();
		BigInteger k;
		do{
			k = new BigInteger(mLens-1, secureRandom);
			n=k.gcd(p.subtract(p.subtract(BigInteger.ONE)));
			
		}while(!n.equals(BigInteger.ONE));

		return k;
	}
	
	private static BigInteger computeA(BigInteger p, BigInteger g, BigInteger k)
	{
		// IMPLEMENT THIS FUNCTION;
		BigInteger r;
		r=g.modPow(k, p);
		return r;
	}

	private static BigInteger computeB(	String message, BigInteger d, BigInteger a, BigInteger k, BigInteger p)
	{
		// IMPLEMENT THIS FUNCTION;
		String cypher_message=encryption(message);
		BigInteger sub1=p.subtract(BigInteger.ONE);
		BigInteger msg_hash=new BigInteger(cypher_message.getBytes());
		BigInteger da=d.multiply(a);
		BigInteger t1=msg_hash.subtract(da);
		try{
			BigInteger t2=k.modInverse(sub1);
			BigInteger t3=t1.multiply(t2);
			BigInteger result=t3.mod(sub1);
			return result;
		}catch(ArithmeticException e){
			return null;
		}
		
	}
	private static String encryption(String str){
		try{
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte buf[] = str.getBytes();
			md.update(buf);
			byte digest[]=md.digest();
			String Md5_message= DatatypeConverter.printHexBinary(digest).toUpperCase();
			return Md5_message;
		}catch(NoSuchAlgorithmException e){
			e.printStackTrace();
			return null;
		}

	}

	public static void main(String[] args) throws Exception 
	{
		String message = "The quick brown fox jumps over the lazy dog.";

		String host = "localhost";
		int port = 7999;
		Socket s = new Socket(host, port);
		ObjectOutputStream os = new ObjectOutputStream(s.getOutputStream());

		// You should consult BigInteger class in Java API documentation to find out what it is.
		BigInteger y, g, p; // public key
		BigInteger d; // private key

		int mStrength = 1024; // key bit length
		SecureRandom mSecureRandom = new SecureRandom(); // a cryptographically strong pseudo-random number

		// Create a BigInterger with mStrength bit length that is highly likely to be prime.
		// (The '16' determines the probability that p is prime. Refer to BigInteger documentation.)
		p = new BigInteger(mStrength, 16, mSecureRandom);
		
		// Create a randomly generated BigInteger of length mStrength-1
		g = new BigInteger(mStrength-1, mSecureRandom);
		d = new BigInteger(mStrength-1, mSecureRandom);

		y = computeY(p, g, d);

		// At this point, you have both the public key and the private key. Now compute the signature.

		BigInteger k = computeK(p);
		BigInteger a = computeA(p, g, k);
		BigInteger b = computeB(message, d, a, k, p);
		
		//eliminate the scenario b is null
		while (b == null){
			p = new BigInteger(mStrength, 16, mSecureRandom);

			// Create a randomly generated BigInteger of length mStrength-1
			g = new BigInteger(mStrength-1, mSecureRandom);
			d = new BigInteger(mStrength-1, mSecureRandom);

			y = computeY(p, g, d);

			// At this point, you have both the public key and the private key. Now compute the signature.

			k = computeK(p);
			a = computeA(p, g, k);
			b = computeB(message, d, a, k, p);
		}
		
		// send public key
		os.writeObject(y);
		os.writeObject(g);
		os.writeObject(p);

		// send message
		os.writeObject(message);
		
		// send signature
		os.writeObject(a);
		os.writeObject(b);
		
		s.close();
	}
}