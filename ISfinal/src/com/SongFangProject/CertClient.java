package com.SongFangProject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;
import java.util.Date;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CertClient {

    public static X509Certificate readX509Certificate(final String certPath) throws CertificateException, FileNotFoundException {

        InputStream is = new FileInputStream(certPath);
        CertificateFactory cFac = CertificateFactory.getInstance("X.509");
        X509Certificate xct = (X509Certificate) cFac.generateCertificate(is);
        return xct;
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureArray = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureArray);
    }

    public static String encrypt(String message, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = encryptCipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static void main(String[] args) throws Exception {
        X509Certificate cert = readX509Certificate("x509.cer");
        System.out.println(String.format("Expiration at: %s", cert.getNotAfter()));

        try {
            Date now = new Date();
            cert.checkValidity(now);
        }catch (CertificateExpiredException | CertificateNotYetValidException e){
            System.out.println("Certificate expired");
        }
        System.out.println("Certificate has not expired");

        Socket s = new Socket("localhost", 7999);
        ObjectInputStream is = new ObjectInputStream(s.getInputStream());
        String cipherCert = (String)is.readObject();
        if (verify(cert.toString(), cipherCert, cert.getPublicKey())){
            System.out.println("Verified! Valid Certificate");
        }else{
            System.out.println("Denied!");
        }

        String message = "Information Security is hard!";
        System.out.println("Plain text: \n" + message);
        String encrypted = encrypt(message, cert.getPublicKey());
        System.out.println("Encryption text: \n" + encrypted);
        ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
        out.writeObject(encrypted);
    }
}

