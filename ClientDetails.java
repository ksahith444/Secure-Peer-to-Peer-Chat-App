package client;

import javax.crypto.SecretKey;

public class ClientDetails {

	public char clientid;
	public int port;
	public String username;
	public String password;	
	public SecretKey secretkey;
	
	public ClientDetails( char id, int port, String clientId, String pass){
		this.clientid = id;
		this.port = port;
		this.username =clientId;
		this.password =pass;
	}
}