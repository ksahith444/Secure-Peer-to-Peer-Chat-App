package client;

import java.io.Serializable;
import javax.crypto.SecretKey;

public class Message implements Serializable{

	private static final long serialVersionUID = 1L;
	public SecretKey secretkey;
	public char clientId;
	public String username;
	public String password;
	public char otherClientId;
	public SecretKey sharedkey;
    public byte[] encryptedtgt;
    public byte[] encryptedmtc;
    public int port;
    public byte[] encrypttimestamp;
    public String msg;
	
	public Message(String msg){	
		this.msg = msg;
	}
	public Message(){		
	}

}
