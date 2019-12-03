package com.SongFangProject;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Date;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

public class ProtectedClient
{
	public void sendAuthentication(String user, String password, OutputStream outStream) throws IOException, NoSuchAlgorithmException 
	{
		DataOutputStream out = new DataOutputStream(outStream);

		// IMPLEMENT THIS FUNCTION.
		Date date = new Date();
		long currentTime = date.getTime();
		Random rand = new Random();
		double num = rand.nextDouble();

		//send user information to server
		out.writeBytes(user);
		out.writeByte('\n');
		out.writeBytes(String.valueOf(currentTime));
		out.writeByte('\n');
		out.writeBytes(String.valueOf(num));
		out.writeByte('\n');

		// Second Encryption
		date = new Date();
		long curr2 = date.getTime();
		double num2 = rand.nextDouble();
		byte[] cipher = Protection.makeDigest(Protection.makeDigest(user, password, currentTime, num), curr2, num2);
		String cipherStr = DatatypeConverter.printHexBinary(cipher).toUpperCase();

		//send timestamp2 and random number2 to server
		out.writeBytes(String.valueOf(curr2));
		out.writeByte('\n');
		out.writeBytes(String.valueOf(num2));
		out.writeByte('\n');

		//send cipher text to server;
		out.writeBytes(cipherStr);
		out.flush();

	}

	public static void main(String[] args) throws Exception 
	{
		String host = "localhost";
		int port = 7999;
		String user = "George";
		String password = "abc123";
		Socket s = new Socket(host, port);

		ProtectedClient client = new ProtectedClient();
		client.sendAuthentication(user, password, s.getOutputStream());

		s.close();
	}
}