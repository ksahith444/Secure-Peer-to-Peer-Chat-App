package client;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;

public class Server implements Runnable{
	
	private Socket socket;
	private SecretKey sessionkey;
	public MainServer ms ;	
	
	public Server(Socket socket, MainServer ms) {
		this.socket = socket;
		this.ms = ms;
	}

	@Override
	public void run() {
		try {
			go();
		} catch (InvalidKeyException | NoSuchAlgorithmException | ClassNotFoundException | NoSuchPaddingException
				| IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
	}
	
    public void go() throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException
    {
    	//Server server = new Server();
		//KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		//server.secretkey = keyGen.generateKey();
    	//server.FileParser();
    	//server.GenerateKeys();
    	
        //ServerSocket serverSocket = new ServerSocket(25000);
        //System.out.println("Server Started and listening to the port 25000");

       //while(true)
       //{
          //socket = serverSocket.accept();
          boolean alive = true;
          ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
  		  ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
          
  		while(alive){
  			
			Pack p=null;
			try{
				p = (Pack)inStream.readObject();
			}catch(EOFException e){
				alive=false;
			}
			
			if(p!=null){
				if(p.header==1){  
					
					byte[] encMsgBytes = p.encMsgByte;
					//byte[] symkeyencrypted = p.Aeskeyencryptedbyrsa;
					
			    	//byte[] msgBytes = server.decrypt(encMsgBytes);
			    	Message detailsMsg = (Message) deserialize(encMsgBytes);
			    	char clientId = detailsMsg.clientId;	
			    	String username = detailsMsg.username;
			    	String password = detailsMsg.password;
			    	if(username.equals(ms.clients.get(clientId).username) && password.equals(ms.clients.get(clientId).password)){
			    		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			    		sessionkey = keyGen.generateKey();
			    		
			    		TicketGrantingTicket tgt  = new TicketGrantingTicket();
			    		tgt.clientId = clientId;
			    		tgt.secretkey = sessionkey;	    		
			    		byte[] tgtbytes = serialize(tgt);
			    		byte[] tgtencryptdata = symEncrypt(tgtbytes);	
			    		
			    	    byte[] key = password.getBytes("UTF-8");
			    	    MessageDigest sha = MessageDigest.getInstance("SHA-1");
			    	    key = sha.digest(key);
			    	    key = Arrays.copyOf(key, 16);
			    	    SecretKeySpec hashOfPassKey = new SecretKeySpec(key, "AES");
			    	    
			    	    Message respMsgfor1 = new Message();
			    	    respMsgfor1.secretkey = sessionkey;
			    	    respMsgfor1.encryptedtgt = tgtencryptdata;			    	    
			    	    byte[] respMsgfor1bytes = serialize(respMsgfor1);
			    	    byte[] respMsgfor1encrypted = encrypt(respMsgfor1bytes, hashOfPassKey);
			    	    
			    	    Pack resMsg = new Pack(2, respMsgfor1encrypted,"Success");
			    	    outStream.writeObject(resMsg);
			    	    
			    	}
			    	else{
			    		Pack resMsg = new Pack("failed");
			    		outStream.writeObject(resMsg);
			    	}
			    }
				
				if(p.header == 3){
						byte[] encMsgBytes = p.encMsgByte;
						//byte[] msgBytes = server.decrypt(encMsgBytes);
						Message detailsMsg = (Message) deserialize(encMsgBytes);
						char otherClientId = detailsMsg.otherClientId;
						char clientId = detailsMsg.clientId;
						//System.out.println(clientId);
						
						if(ms.clients.keySet().contains(otherClientId)){
							
							KeyGenerator keyGen = KeyGenerator.getInstance("AES");
							SecretKey sharedkey = keyGen.generateKey();
				    		MessageToClient mtc  = new MessageToClient();
				    		mtc.clientId = clientId;
				    		mtc.sharedkey = sharedkey ;	
				    		//System.out.println(ms.clients.get(clientId).port);
				    		mtc.port = ms.clients.get(clientId).port;
				    		byte[] mtcbytes = serialize(mtc);
				    		
				    	    byte[] key = ms.clients.get(otherClientId).password.getBytes("UTF-8");
				    	    MessageDigest sha = MessageDigest.getInstance("SHA-1");
				    	    key = sha.digest(key);
				    	    key = Arrays.copyOf(key, 16);
				    	    SecretKeySpec hashOfOtherClientPassKey = new SecretKeySpec(key, "AES");
				    	    
				    		byte[] mtcencryptdata = encrypt(mtcbytes, hashOfOtherClientPassKey);
				    		
							Message msg = new Message();
							msg.otherClientId = otherClientId;
							msg.sharedkey = sharedkey;
							msg.encryptedmtc = mtcencryptdata;
							msg.port = ms.clients.get(otherClientId).port;
							
				    	    byte[] respMsgfor3bytes = serialize(msg);
				    	    byte[] respMsgfor3encrypted = encrypt(respMsgfor3bytes, sessionkey);
							
				    	    Pack resMsg = new Pack(5, respMsgfor3encrypted);
				    	    outStream.writeObject(resMsg);	
				    	    
						}
						else{
							System.out.println("Client " + otherClientId + " is not a authorised client");
						}	
						
				}
				
			 }              
  		  }
      // }
    }

/*	private void GenerateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	    keyPairGenerator.initialize(1024); //1024 used for normal securities
	    KeyPair keyPair = keyPairGenerator.generateKeyPair();
	    publicKey = keyPair.getPublic();
	    privateKey = keyPair.getPrivate();
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
	    System.out.println("public and private keys generated");
	    SaveKeys(new File("server_public.key") , rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
	    
	}
   
    private static void SaveKeys(File fileName, BigInteger mod, BigInteger exp) throws IOException {
	    FileOutputStream fos = new FileOutputStream(fileName);;
	    ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(fos));		  
	    oos.writeObject(mod);
	    oos.writeObject(exp);   	   
	    if(oos != null)
			oos.close();	    
	    if(fos != null)
			fos.close();	
	    System.out.println("public key stored to file");
	 }*/
    
	
	PrivateKey readPrivateKeyFromFile(String keyFileName) throws IOException {
		  InputStream in = new FileInputStream(keyFileName);
		  ObjectInputStream oin =
		    new ObjectInputStream(new BufferedInputStream(in));
		  try {
		    BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PrivateKey priKey = fact.generatePrivate(keySpec);
		    return priKey;
		  } catch (Exception e) {
		    throw new RuntimeException("Spurious serialization error", e);
		  } finally {
		    oin.close();
		  }
	}
		    
    public byte[] decrypt(byte[] data) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {	   	    
	    Cipher cipher = Cipher.getInstance("RSA");
	    PrivateKey privateKey = readPrivateKeyFromFile("server1_private.key");
	    cipher.init(Cipher.DECRYPT_MODE, privateKey);
	    byte[] descryptedData = cipher.doFinal(data);	   
	    return descryptedData;  
	 }
   
	public Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
	    ByteArrayInputStream in = new ByteArrayInputStream(data);
	    ObjectInputStream is = new ObjectInputStream(in);
	    return is.readObject();
	}
	
	public byte[] serialize(TicketGrantingTicket tgt) throws IOException{
		ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(tgt);
        return b.toByteArray();
	}
	
	public byte[] serialize(MessageToClient mtc) throws IOException{
		ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(mtc);
        return b.toByteArray();
	}
	
	public byte[] serialize(Message msg) throws IOException{
		ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(msg);
        return b.toByteArray();
	}
	
    public byte[] encrypt(byte[] objToEncrypt, SecretKeySpec secretkey ) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");       
        cipher.init(Cipher.ENCRYPT_MODE, secretkey);        
        byte[] encrypteddate = cipher.doFinal(objToEncrypt);
        return encrypteddate;
    }
    
    private byte[] encrypt(byte[] objToEncrypt, SecretKey secretkey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");       
        cipher.init(Cipher.ENCRYPT_MODE, secretkey);        
        byte[] encrypteddate = cipher.doFinal(objToEncrypt);
        return encrypteddate;
	}
    
	public byte[] symEncrypt(byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.ENCRYPT_MODE, ms.secretkey);
		byte[] encryptedData = c.doFinal(data);
		return encryptedData;
	}

}

