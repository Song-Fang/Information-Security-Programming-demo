package com.SongFangProject;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;

public class CipherClient {
	public static void main(String[] args) throws Exception {
		String message = "The quick brown fox jumps over the lazy dog.";
		String host = "localhost";
		int port = 7999;
		Socket s = new Socket(host, port);

		// YOU NEED TO DO THESE STEPS:
		// -Generate a DES key.
		// -Store it in a file.
		// -Use the key to encrypt the message above and send it over socket s to the
		// server.
		KeyGenerator k = KeyGenerator.getInstance("DES");
		SecureRandom random = new SecureRandom();

		k.init(random);

		Key key = k.generateKey();
		String cypherKey = Base64.getEncoder().encodeToString(key.getEncoded());

		System.out.println("The DES key is " + cypherKey);

		// Store key in local file
		FileWriter storeKey = new FileWriter("key.txt");
		BufferedWriter bf = new BufferedWriter(storeKey);
		bf.write(cypherKey);
		bf.close();

		// encrypt the string
		// send encrypted message to server
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		ObjectOutputStream cipherOut = new ObjectOutputStream(s.getOutputStream());
		
		// convert message to input to print
		byte[] input = message.getBytes();
		byte[] ciphertext = cipher.doFinal(input);
		
		//output encryption text to console
		String ciphertextStr = DatatypeConverter.printHexBinary(ciphertext);
		System.out.println("Encrption text is " + ciphertextStr);

		cipherOut.writeObject(ciphertext);
		// close stream
		s.close();
	}
}