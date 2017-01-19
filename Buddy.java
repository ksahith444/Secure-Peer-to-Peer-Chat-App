package client;

import javax.crypto.SecretKey;

public class Buddy {
	public SecretKey sharedkey;
	public int port;
	
	public Buddy(SecretKey sh, int port){
		this.sharedkey = sh;
		this.port = port;
	}

}
