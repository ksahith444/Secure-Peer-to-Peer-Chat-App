package client;

import java.io.Serializable;

public class MessageMAC implements Serializable{

	private static final long serialVersionUID = 1L;
	public  byte[] msgByte;
	public byte[] digest;
	
	public MessageMAC(byte[] byteMsg, byte[] hmac){
		this.msgByte = byteMsg;
		this.digest = hmac;
	}
}
