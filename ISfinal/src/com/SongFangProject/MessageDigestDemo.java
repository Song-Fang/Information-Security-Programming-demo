package com.SongFangProject;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class MessageDigestDemo {
    public static void main(String[] args){
        MyAlgorithms ma = new MyAlgorithms();
        String input;
        System.out.print("Please enter the plain text: ");
        Scanner sc = new Scanner(System.in);
        input = sc.nextLine();

        final String md5Text = ma.messageEncryption(input, "MD5");
        final String shaText = ma.messageEncryption(input, "SHA");

        System.out.print("The encrypted text by using MD5 is: ");
        System.out.print(md5Text + "\n");
        System.out.print("The encrypted text by using SHA is: ");
        System.out.print(shaText + "\n");
        sc.close();
    }
}

class MyAlgorithms{

    public String messageEncryption(String message, String algorithm){
        try{
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte buf[] = message.getBytes();
            md.update(buf);
            byte digest[]=md.digest();
            String Md5_message= DatatypeConverter.printHexBinary(digest).toUpperCase();
            return Md5_message;
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        }
    }
}

