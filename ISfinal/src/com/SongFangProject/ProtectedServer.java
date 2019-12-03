package com.SongFangProject;
import java.io.*;
import java.net.*;
import java.security.*;


import javax.xml.bind.DatatypeConverter;

public class ProtectedServer
{
	public boolean authenticate(InputStream inStream) throws IOException, NoSuchAlgorithmException 
	{
		DataInputStream in = new DataInputStream(inStream);

		// IMPLEMENT THIS FUNCTION.
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		String user = reader.readLine();
		long time1 = Long.valueOf(reader.readLine());
		double num1 = Double.valueOf(reader.readLine());

		long time2 = Long.valueOf(reader.readLine());
		double num2 = Double.valueOf(reader.readLine());

		String cipher = reader.readLine();
		reader.close();
		String pwd = lookupPassword(user);
		byte[] currCipher = Protection.makeDigest(Protection.makeDigest(user, pwd, time1, num1), time2, num2);
		String expected = DatatypeConverter.printHexBinary(currCipher).toUpperCase();
		return expected.equals(cipher);
	}

	protected String lookupPassword(String user) { return "abc123"; }

	public static void main(String[] args) throws Exception 
	{
		int port = 7999;
		ServerSocket s = new ServerSocket(port);
		Socket client = s.accept();

		ProtectedServer server = new ProtectedServer();

		if (server.authenticate(client.getInputStream()))
		  System.out.println("Client logged in.");
		else
		  System.out.println("Client failed to log in.");

		s.close();
	}
}