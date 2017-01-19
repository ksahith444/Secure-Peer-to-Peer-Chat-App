package client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MainServer {

	HashMap< Character , ClientDetails> clients;
	//private PrivateKey privateKey;
	//private PublicKey publicKey;
	public SecretKey secretkey;
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NumberFormatException, IOException {
		MainServer ms = new MainServer();
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		ms.secretkey = keyGen.generateKey();
		ms.FileParser();
		
		ServerSocket servSock = new ServerSocket(25000);
		System.out.println("Server started on port 25000");
		while(true){	
			Socket sock = servSock.accept();
			Thread th = new Thread(new Server(sock,ms));
			th.start();
		}	
	}

	public void FileParser() throws NumberFormatException, IOException{	   
		   clients = new HashMap< Character, ClientDetails>();
		   File file = new File("/Users/sahith/Desktop/InstantMessageApp/src/client/passwdfile");
		   BufferedReader reader = null;
		   reader = new BufferedReader(new FileReader(file));
		   String text = null;
		   while ((text = reader.readLine()) != null) {	    	  
		    	String[] fields = text.split(",");	    	   
		    	ClientDetails client = new ClientDetails(fields[0].charAt(0), Integer.parseInt(fields[1]), fields[2], fields[3]);   
		        clients.put(fields[0].charAt(0), client);
		    }
		   if (reader != null){
		         reader.close();
		    }	   	
	    }

}
