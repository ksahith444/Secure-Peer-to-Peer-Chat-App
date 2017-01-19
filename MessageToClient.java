package client;

import java.io.Serializable;

import javax.crypto.SecretKey;

public class MessageToClient implements Serializable{

	private static final long serialVersionUID = 1L;
	public char clientId;
	public int port; 
	public SecretKey sharedkey;
	
}
