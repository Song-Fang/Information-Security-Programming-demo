package com.SongFangProject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CertServer {
	private static final int PORT = 7999;
	private static PublicKey publicKey;
	private static PrivateKey privateKey;

	public static KeyStore getKeyStore(final String jksPath, final String jksPassword) throws KeyStoreException,
			IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(jksPath), jksPassword.toCharArray());
		Enumeration aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			String alias = (String) aliases.nextElement();
			if (keyStore.isKeyEntry(alias)) {
				Key key = keyStore.getKey(alias, jksPassword.toCharArray());
				if (key instanceof PrivateKey) {
					privateKey = (PrivateKey) key;
				}
			}
		}
		return keyStore;
	}

	public static String decrypt(byte[] cipherText, PrivateKey pk) throws NoSuchPaddingException,
			NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
		Cipher decriptCipher = Cipher.getInstance("RSA");
		decriptCipher.init(Cipher.DECRYPT_MODE, pk);
		return new String(decriptCipher.doFinal(cipherText), UTF_8);
	}

	public static X509Certificate getX509CertificateFromKeystore(final KeyStore keyStore, final String keyAlias)
			throws KeyStoreException {
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
		publicKey = cert.getPublicKey();
		return cert;
	}

	public static String signCert(Certificate certificate)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privateKey);
		privateSignature.update(certificate.toString().getBytes(UTF_8));

		byte[] signature = privateSignature.sign();

		return Base64.getEncoder().encodeToString(signature);
	}

	public static void main(String[] args) throws KeyStoreException, CertificateException, NoSuchAlgorithmException,
			IOException, UnrecoverableKeyException, SignatureException, InvalidKeyException, ClassNotFoundException,
			NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
		KeyStore keystore = getKeyStore("songfang.keystore", "666666");
		X509Certificate x509 = getX509CertificateFromKeystore(keystore, "songfang");
		System.out.println("The x509 certificate: ");
		System.out.println(x509.toString());

		ServerSocket s = new ServerSocket(PORT);
		Socket client = s.accept();
		ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());

		String cipherCert = signCert(x509);
		out.writeObject(cipherCert);
		ObjectInputStream is = new ObjectInputStream(client.getInputStream());
		String ciphterText = (String) is.readObject();

		byte[] ciphterTextBytes = Base64.getDecoder().decode(ciphterText);
		String plainText = decrypt(ciphterTextBytes, privateKey);
		System.out.println("Plain text: \n" + plainText);
	}
}
