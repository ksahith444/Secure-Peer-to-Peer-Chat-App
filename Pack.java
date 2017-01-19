package client; 

import java.io.Serializable;

public class Pack implements Serializable{

	private static final long serialVersionUID = 1L;
	public int header;
	public byte[] encMsgByte;
	public String response;
	public byte[] Aeskeyencryptedbyrsa;
	char clientId;
	
	public Pack(int head,byte[] dat,String reponse){
		this.header = head;
		this.encMsgByte = dat;
		this.response = reponse;
	}
	public Pack(int head,byte[] dat){
		this.header = head;
		this.encMsgByte = dat;
		
	}
	public Pack(String reponse){
		this.response = reponse;
	}
	
	public Pack(int head,byte[] dat,byte[] symkeyencypted){
		this.header = head;
		this.encMsgByte = dat;
		this.Aeskeyencryptedbyrsa = symkeyencypted;
	}
	
	public Pack(int head,byte[] dat, char clientId){
		this.header = head;
		this.encMsgByte = dat;
		this.clientId = clientId;
	}
	
}
