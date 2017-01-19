package client;

import java.io.Serializable;

import javax.crypto.SecretKey;

public class TicketGrantingTicket implements Serializable {

	private static final long serialVersionUID = 1L;
	public char clientId;
	public SecretKey secretkey;

}
