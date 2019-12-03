package com.SongFangProject;

import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Base64;

public class PubKeyServer {
	
	private final static int PORT = 7999;


  public static void main(String[] args) throws Exception {
     
      PubKeyTool pkt = new PubKeyTool(2048);
      
      pkt.writeToFile("User2PublicKey.txt", pkt.getPublicKey());

      System.out.println("The public key for User2 is: " + Base64.getEncoder().encodeToString(pkt.getPublicKey().getEncoded()));
      System.out.println("The private key for User2 is:: " + Base64.getEncoder().encodeToString(pkt.getPrivateKey().getEncoded()));

      ServerSocket s = new ServerSocket(PORT);
      Socket client = s.accept();
      ObjectInputStream is = new ObjectInputStream(client.getInputStream());

      PublicKey clientPublicKey =  pkt.readPublicKeyFromFile("User1PublicKey.txt");

      String ciphertext = (String) is.readObject();
      System.out.println("ciphertext is :\n" + ciphertext);

      String encryptedMsg = (String) is.readObject();

      
      byte[] signature = PubKeyTool.decrypt(PubKeyTool.base64String2byteArray(ciphertext), pkt.getPrivateKey());
      System.out.println("Signature is : \n" + PubKeyTool.byteArray2Base64String(signature));
      byte[] plainTxt = PubKeyTool.decrypt(PubKeyTool.base64String2byteArray(encryptedMsg), pkt.getPrivateKey());

      
      if (PubKeyTool.verifySignature(plainTxt, signature, clientPublicKey)){
          System.out.println("Signature is valid");
      }else{
          System.out.println("Signature is invalid");
      }
      System.out.println("The plain text is: " + new String(plainTxt));
      s.close();
  }
}
