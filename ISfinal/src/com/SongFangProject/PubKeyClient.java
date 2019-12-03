package com.SongFangProject;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class PubKeyClient {
	private static int PORT = 7999;

	public static void main(String[] args) throws Exception {

		PubKeyTool pbt = new PubKeyTool(512);

		pbt.writeToFile("User1PublicKey.txt", pbt.getPublicKey());
		System.out.println("The private key for User1 is: " + Base64.getEncoder().encodeToString(pbt.getPrivateKey().getEncoded()));
		System.out.println("The public key for User2 is: " + Base64.getEncoder().encodeToString(pbt.getPublicKey().getEncoded()));
		

		final String host = "localhost";
		Socket s = new Socket(host, PORT);

		Key serverPublicKey = pbt.readPublicKeyFromFile("User2PublicKey.txt");

		System.out.println("Server public key: " + Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));

		Scanner scanner = new Scanner(System.in);
		System.out.println("Input your message: ");
		final String msg = scanner.nextLine();

	
		byte[] signature = PubKeyTool.sign(msg.getBytes(), pbt.getPrivateKey());
		
		byte[] cipherText = PubKeyTool.encrypt(signature, serverPublicKey);

		
		byte[] encryptedMsg = PubKeyTool.encrypt(msg.getBytes(UTF_8), serverPublicKey);


		System.out.println("User Signature: \n" + PubKeyTool.byteArray2Base64String(signature));
		System.out.println("Encryption Text: \n" + PubKeyTool.byteArray2Base64String(cipherText));
		ObjectOutputStream os = new ObjectOutputStream(s.getOutputStream());

		os.writeObject(PubKeyTool.byteArray2Base64String(cipherText));
		os.writeObject(PubKeyTool.byteArray2Base64String(encryptedMsg));
		os.close();
	}
}


//Tool class 
//Used to generate publicKey, PrivateKey and signature
class PubKeyTool {

	private PrivateKey privateKey;
	private PublicKey publicKey;


	public PubKeyTool(int size) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(size, new SecureRandom());
		KeyPair pair = keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}

	public void writeToFile(String fileName, Key key) throws IOException {
		byte[] keyBytes = key.getEncoded();
		FileOutputStream keyfos = new FileOutputStream(fileName);
		keyfos.write(keyBytes);
		keyfos.close();
	}

	public static PublicKey readPublicKeyFromFile(String fileName)
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public static PrivateKey readPrivateKeyFromFile(String fileName)
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public static byte[] encrypt(byte[] bytes, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, key);
		return encryptCipher.doFinal(bytes);
	}

	public static byte[] decrypt(byte[] cipherText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
		Cipher decriptCipher = Cipher.getInstance("RSA");
		decriptCipher.init(Cipher.DECRYPT_MODE, key);
		return decriptCipher.doFinal(cipherText);
	}

	public static String byteArray2Base64String(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	public static byte[] base64String2byteArray(String text) {
		return Base64.getDecoder().decode(text);
	}

	public static byte[] sign(byte[] message, PrivateKey privateKey) throws Exception {
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privateKey);
		privateSignature.update(message);
		return privateSignature.sign();
	}

	public static boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws Exception {
		Signature publicSignature = Signature.getInstance("SHA256withRSA");
		publicSignature.initVerify(publicKey);
		publicSignature.update(message);
		return publicSignature.verify(signature);
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

}