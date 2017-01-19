package client;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;


public class MessageAuthCode {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException{
		MessageAuthCode mac = new MessageAuthCode();
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		SecretKey sk = keyGen.generateKey();
		String str = "Hello Doctor heart miss aaye";
		byte[] b = mac.getDigest(str);
		byte[] hb = mac.getHMAC(str,sk);
		mac.checkIntegrityHMac(hb,"Hello Doctor heart mis aaye",sk);
		
	}
	
	public byte[] getDigest(String str) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(str.getBytes());
		byte[] hash = md.digest();
		return hash;
	}
	
	public void checkIntegrity(byte[] b, String str) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(str.getBytes());
		byte[] hash = md.digest();
		
		if(Arrays.equals(b, hash)){
			System.out.println("Integrity maintained");
			
		}else{
			System.out.println("Damaged");
		}
	}
	
	public void checkIntegrityHMac(byte[] hb,String str,SecretKey sk) throws NoSuchAlgorithmException, InvalidKeyException{
		Mac mc = Mac.getInstance("HmacSHA256");
		mc.init(sk);
		byte[] hb1  = mc.doFinal(str.getBytes());
		if(Arrays.equals(hb, hb1)){
			System.out.println("Integrity maintained");
			
		}else{
			System.out.println("Damaged");
		}		
	}
	
	public byte[] getHMAC(String str,SecretKey sk) throws InvalidKeyException, NoSuchAlgorithmException{
		Mac mc = Mac.getInstance("HmacSHA256");
		
		mc.init(sk);
		byte[] hb  = mc.doFinal(str.getBytes());
		return hb;
	}
}
