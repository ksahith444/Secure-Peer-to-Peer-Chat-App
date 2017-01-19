package client;

import java.net.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;

public class Client {

	public char clientID;
	public String password;
	public String username;
	public int port;
	public Map<Character, Buddy> buddyList;

	public static void main(String args[]) throws UnknownHostException, IOException, NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException, ClassNotFoundException {
		Client cl = new Client();
		cl.clientID = args[0].charAt(0);
		cl.port = Integer.parseInt(args[1]);
		cl.buddyList = new HashMap<Character, Buddy>();		
		cl.startRequests();
	}


	private void startRequests() throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, ClassNotFoundException {
		
    	boolean closeClient = true; 
    	
    	while(closeClient){
    		
    		System.out.println("**************** Authenticate ********************");
    		System.out.println("Please enter your Username");
    		Scanner sc = new Scanner(System.in);
    		BufferedReader bReader = new BufferedReader(new InputStreamReader(System.in));
    		username = sc.next();
    		System.out.println("Please enter your Password");
    		password = sc.next();
    		
    		Message msg = new Message();
    		msg.username = username;
    		msg.password = password;
    		msg.clientId = clientID;
    		
  		
    		byte[] reqmsg1 = serialize(msg);
    		
    	/*	KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    		SecretKey secretkeyforrsa = keyGen.generateKey();
    		byte[] Aeskeyencryptedbyrsa = encrypt(secretkeyforrsa.getEncoded());
    		byte[] reqMsg1encrypted = symEncrypt(reqmsg1,secretkeyforrsa );  
    		Pack reqmsg = new Pack(1, reqMsg1encrypted, Aeskeyencryptedbyrsa);  		
    		*/   	
    		Pack reqmsg = new Pack(1, reqmsg1);
  		
    		Socket socket = new Socket(InetAddress.getByName("localhost"), 25000);
    		ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
    		outputStream.writeObject(reqmsg);
	    
    		ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
	    
    		Pack respfor1 = (Pack)inStream.readObject();
    		
    		if(respfor1.response.equals("Success")){	  
    			
    			System.out.println("Authentication is Successfull! Welcome");
    			boolean exit = true;
    			while(exit){
    				
    				int option ;
    				while(true){
    					System.out.println("Clients in the buddylist");
    					for(Character clienId: buddyList.keySet()){
    						System.out.print(clienId + ", ");
    					}
    					System.out.println("\n");
    					System.out.println("**************** Menu ********************");
    					System.out.println("1 : If you want to talk to new client");
    					System.out.println("2 : If you want to talk to a client in the buddylist");
    					System.out.println("3 : Listen for other client requests");
    					System.out.println("4 : Remove client from the buddyList");    				
    					System.out.println("5 : Exit");    			
    					System.out.print("\nEnter option : ");  
    					
    					
    					String opt = bReader.readLine();
    					try{
    						option = Integer.parseInt(opt);
    					}catch(Exception e){
    						option = 0;
    					}
    					if(option >= 1 && option <= 5){
    						break;
    					}
    					else
    						System.out.println("please enter correct option");
    				}
    			
    				if(option == 1){
    				
    					byte[] key = password.getBytes("UTF-8");
    					MessageDigest sha = MessageDigest.getInstance("SHA-1");
    					key = sha.digest(key);
    					key = Arrays.copyOf(key, 16);
    					SecretKeySpec hashOfPassKey = new SecretKeySpec(key, "AES");
	    
    					byte[] respmsgfor1 = respfor1.encMsgByte;
    					byte[] decryptedresfor1 = decrypt(respmsgfor1, hashOfPassKey);
    					Message detailsMsg = (Message) deserialize(decryptedresfor1);
    					SecretKey sessionkey = detailsMsg.secretkey;
        
    					System.out.println("Enter the ClientId you wanna chat with?");
    					char otherClientId = sc.next().charAt(0);
    					System.out.println("Please wait!!!! Obtaining shared key for " + otherClientId + " from server");

    					/* timestamp encryption */
	    	
    					Message reqmsg3 = new Message();
    					reqmsg3.encryptedtgt = detailsMsg.encryptedtgt;
    					reqmsg3.otherClientId = otherClientId;
    					reqmsg3.clientId = clientID;
	    	
    					byte[] reqMsg3bytes = serialize(reqmsg3);
	    	
    					Pack resMsg = new Pack(3, reqMsg3bytes);
    					outputStream.writeObject(resMsg);	    	
    					
    					Pack resp = (Pack)inStream.readObject();
    					if(resp.header == 4){
    						socket.close();
    						outputStream.close();
    						inStream.close();
    					}
    					byte[] respmsg = resp.encMsgByte;
    					byte[] msgBytes = decrypt(respmsg, sessionkey);
    					Message decryptmsg = (Message) deserialize(msgBytes);
    					byte[] encrptedmsgtoclient = decryptmsg.encryptedmtc;
    					SecretKey sharedkey = decryptmsg.sharedkey;
    					int port = decryptmsg.port;
    					
    					// Client to Client Authentication 
    					// send encrypted time stamp and ticket to client 
    					System.out.println("sending shared key to client and authenticating");
    					Socket sockclient = new Socket(InetAddress.getByName("localhost"), port);
    					ObjectOutputStream outputStreamclient = new ObjectOutputStream(sockclient.getOutputStream());
    					ObjectInputStream inStreamclient = new ObjectInputStream(sockclient.getInputStream());
    					
    					long timestamp = System.currentTimeMillis();
    					byte[] timestampbytes = longToBytes(timestamp);
    					byte[] encryptedtimestamp = symEncrypt(timestampbytes, sharedkey);
    					
    					Message msgtoclient = new Message();
    					msgtoclient.encryptedmtc = encrptedmsgtoclient;
    					msgtoclient.encrypttimestamp = encryptedtimestamp;
    					
    					byte[] msgtoclientbytes = serialize(msgtoclient);
    					
    					Pack pc = new Pack(5, msgtoclientbytes );
    					
    					outputStreamclient.writeObject(pc);
    					
    					//response from client incrementing the time stamp 
    					resp = (Pack)inStreamclient.readObject();
    					byte[] incrementedtimestamp = resp.encMsgByte;
    					byte[] decryptedtimestamp = symDecrypt(incrementedtimestamp, sharedkey);
    					long inctimestamp = bytesToLong(decryptedtimestamp);
    					
    					if(inctimestamp == timestamp+1){
    						if(!buddyList.containsKey(otherClientId)){
    							Buddy b = new Buddy(sharedkey, port);
    							buddyList.put(otherClientId, b);
    						}
    						System.out.println("Successfully authenticated client");
    						System.out.println("Starting converasatiuon with client");
    						chatWithClient(otherClientId, outputStreamclient, inStreamclient, sharedkey);
    					}
    					else{
    						System.out.println("Sorry could not authenticate client");
    					}
    					sockclient.close();
    				}
    			
    				if(option ==2){
    					System.out.println("Enter the ClientId you wanna chat with from buddylist?");
    					char otherClientId = sc.next().charAt(0);
    				
    					if(buddyList.containsKey(otherClientId)){
    						System.out.println("Client " + otherClientId + " is in the buddylist");
    						System.out.println("Establishing connection with the client.......");
    						chatWithClient(otherClientId);
    					}
    					else{
    						System.out.println(" Sorry !!!Entered client "+ otherClientId + " is not in buddylist");  						
    					}
    					
    				}
    			
    				if(option == 3){
    					System.out.println("Listening for clients requests");
    					ServerSocket servsocket = new ServerSocket(port);
    					Socket sock = servsocket.accept();
    			        ObjectInputStream inStreamnew = new ObjectInputStream(sock.getInputStream());
    			  		ObjectOutputStream outStreamnew = new ObjectOutputStream(sock.getOutputStream());
    			  		boolean counter = true;
    			  		Pack respnew = (Pack)inStreamnew.readObject();
    			  		char client = respnew.clientId;
    			  		SecretKey sharedkeynew = null;
    			  		
			  			if(respnew.header == 5){
			  				counter = false;
			  				byte[] encyptedmsgnew = respnew.encMsgByte;
			  				Message msgnew = (Message) deserialize(encyptedmsgnew);
			  				byte[] encryptedtimestamp = msgnew.encrypttimestamp;
			  				byte[] mtc = msgnew.encryptedmtc;
			  			
			  				byte[] keynew = password.getBytes("UTF-8");
			  				MessageDigest shanew = MessageDigest.getInstance("SHA-1");
			  				keynew = shanew.digest(keynew);
			  				keynew = Arrays.copyOf(keynew, 16);
			  				SecretKeySpec hashedkey = new SecretKeySpec(keynew, "AES");
			    	    
			  				byte[] mtcdecrpted = decrypt(mtc, hashedkey);
			  				MessageToClient mtcobj = (MessageToClient) deserialize(mtcdecrpted);
			  				sharedkeynew = mtcobj.sharedkey;
			  				char neighbourId = mtcobj.clientId;
			  				int neighbourport = mtcobj.port;
			  				
			  				byte[] decryptedtimestamp = decrypt(encryptedtimestamp, sharedkeynew);
			  				long timestampnew = bytesToLong(decryptedtimestamp) + 1;
			  				System.out.println("Incremented timestamp is " + timestampnew);
			  			
			  			
			  				byte[] timsbytes = longToBytes(timestampnew);
			  				byte[] encrypttime = symEncrypt(timsbytes, sharedkeynew);
			  			
			  				Pack pck = new Pack(6, encrypttime);
			  				outStreamnew.writeObject(pck);
			  				if(!buddyList.containsKey(neighbourId)){
			  					Buddy bd = new Buddy(sharedkeynew, neighbourport);
			  					buddyList.put(neighbourId, bd);
			  				}
			  			}
			  			Scanner s = new Scanner(System.in);
			  			
			  			if(sharedkeynew == null || respnew.header == 7){
			  				sharedkeynew = buddyList.get(client).sharedkey;
			  			}
    			  		while(true){
    			  			
    			  			Pack r = null;
    			  			if(counter == true){
    			  				r = respnew;
    			  				counter = false;
    			  			}
    			  			else{
    			  				r = (Pack)inStreamnew.readObject();
    			  			}
        					byte[] encryptedmsg = r.encMsgByte;
        					byte[] msgbytes = symDecrypt(encryptedmsg, sharedkeynew);
        					String ms = new String(msgbytes);
        					System.out.println(ms);
        					if(ms.equalsIgnoreCase("bye")){
        						//s.close();
    			  				servsocket.close();
    			  				inStreamnew.close();
    			  				outStreamnew.close();
    			  				break;
        					}
        					String m = s.nextLine().trim();
        					String m2 = m.replaceAll("(\\r|\\n|\\r\\n)+", "");
        					byte[] valuesDefault = m2.getBytes();
        					byte[] encryp = symEncrypt(valuesDefault, sharedkeynew);
        					Pack rs = new Pack(7, encryp);
        					
        					outStreamnew.writeObject(rs);
   
        					if(m2.equalsIgnoreCase("bye")){
        						//s.close();
        						inStreamnew.close();
    			  				outStreamnew.close();
        						break;
        					}
    			  		}    				
    				}
    			
    				if(option == 4){
    					System.out.println(" Enter the clientId you want to remove ");
    					char clientId = sc.next().charAt(0);
    					if(buddyList.containsKey(clientId)){
    						buddyList.remove(clientId);
    						System.out.println("Client " + clientId + " removed from the buddylist");
    					}
    					else{
    						System.out.println(" Sorry, Client " + clientId + " is not in the buddylist");
    					}
    				}
    			
    				if(option == 5){
    					System.out.println("logging out.....");
    					System.out.println("Thank you");
    					exit = false;
    					socket.close();
    				}
    			}
    		}
    	    else{
    	    	System.out.println("Username and password are incorrect! ");
    	    	System.out.println("please try again");
    	    	socket.close();
    	    	}
    	}
	}

	private void chatWithClient(char otherClientId ) throws UnknownHostException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
		Buddy buddy = buddyList.get(otherClientId);
		SecretKey sharedKey = buddy.sharedkey;
		int port = buddy.port;
		System.out.println(port);
		Socket socketclient = new Socket(InetAddress.getByName("localhost"), port);
		ObjectOutputStream outputStreamforclient = new ObjectOutputStream(socketclient.getOutputStream());
		ObjectInputStream inputStreamforclient = new ObjectInputStream(socketclient.getInputStream());
		
		chatWithClient(otherClientId, outputStreamforclient, inputStreamforclient, sharedKey);
		
		//socketclient.close();
	}

	private void chatWithClient(char otherClientId, ObjectOutputStream outputStreamforclient, ObjectInputStream  inputStreamforclient, SecretKey sharedKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
		
		Scanner sc1 = new Scanner(System.in);
		System.out.println("press enter to send");
		
		String m = sc1.nextLine().trim();
		byte[] valuesDefault = m.getBytes();
		byte[] encryp = symEncrypt(valuesDefault, sharedKey);
		Pack rs = new Pack(7, encryp, clientID);
		
		outputStreamforclient.writeObject(rs);;
		
		while(true){
 		
  			Pack r = (Pack)inputStreamforclient.readObject();
			byte[] encryptedmsg = r.encMsgByte;
			byte[] msgbytes = symDecrypt(encryptedmsg, sharedKey);
			String ms = new String(msgbytes);
			System.out.println(ms);
			if(ms.equals("bye")){
				outputStreamforclient.close();
				inputStreamforclient.close();
				break;
			}
			m = sc1.nextLine().trim();
			String m2 = m.replaceAll("(\\r|\\n|\\r\\n)+", "");
			valuesDefault = m2.getBytes();
			encryp = symEncrypt(valuesDefault, sharedKey);
			rs = new Pack(7, encryp);
			
			outputStreamforclient.writeObject(rs);
			if(m2.equalsIgnoreCase("bye")){
				outputStreamforclient.close();
				inputStreamforclient.close();
				break;
			}			
		}	
	}

	private byte[] decrypt(byte[] respmsg, SecretKey sessionkey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, sessionkey);
		byte[] decryptedresfor1 = cipher.doFinal(respmsg);
		return decryptedresfor1;
	}
	
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
	
	PublicKey readPublicKeyFromFile(String keyFileName) throws IOException {
		  InputStream in = new FileInputStream(keyFileName);
		  ObjectInputStream oin =
		    new ObjectInputStream(new BufferedInputStream(in));
		  try {
		    BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PublicKey pubKey = fact.generatePublic(keySpec);
		    return pubKey;
		  } catch (Exception e) {
		    throw new RuntimeException("Spurious serialisation error", e);
		  } finally {
		    oin.close();
		  }
	}

	public byte[] encrypt(byte[] str)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, ClassNotFoundException {
		PublicKey pubKey = readPublicKeyFromFile("server1_public.key");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] cipherData = cipher.doFinal(str);
		return cipherData;
	}

	public byte[] symEncrypt(byte[] data, SecretKey sk) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.ENCRYPT_MODE, sk);
		byte[] encryptedData = c.doFinal(data);
		return encryptedData;
	}

	public byte[] symDecrypt(byte[] data, SecretKey sk) throws NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.DECRYPT_MODE, sk);
		byte[] decrypted = c.doFinal(data);
		return decrypted;
	}

	public byte[] serialize(Message msg) throws IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream o = new ObjectOutputStream(b);
		o.writeObject(msg);
		return b.toByteArray();
	}

	public Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
		ByteArrayInputStream in = new ByteArrayInputStream(data);
		ObjectInputStream is = new ObjectInputStream(in);
		return is.readObject();
	}
	
	public byte[] longToBytes(long x) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.putLong(x);
	    return buffer.array();
	}
	
	public long bytesToLong(byte[] bytes) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.put(bytes);
	    buffer.flip();//need flip 
	    return buffer.getLong();
	}
	
	/*	public PublicKey readPublicKeyFromFile(String fileName)
	throws IOException, InvalidKeySpecException, ClassNotFoundException, NoSuchAlgorithmException {
FileInputStream fis = new FileInputStream(new File(fileName));
ObjectInputStream ois = new ObjectInputStream(fis);
BigInteger modulus = (BigInteger) ois.readObject();
BigInteger exponent = (BigInteger) ois.readObject();
RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
KeyFactory fact = KeyFactory.getInstance("RSA");
PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
if (ois != null)
	ois.close();
if (fis != null)
	fis.close();
return publicKey;

		
String r =  inputStreamforclient.readObject().toString();
	System.out.println(r);
	if(r.equals("bye")){
			sc1.close();
			outputStreamforclient.close();
			inputStreamforclient.close();
			break;
	}
	m = sc1.nextLine().trim();
	String m2 = m.replaceAll("(\\r|\\n|\\r\\n)+", "");
	outputStreamforclient.writeObject(m2);
	if(m2.equalsIgnoreCase("bye")){
		break;
	}
}*/
}
