/*
 * Inetsec 1 2012 Challenge6
 * DH key exchange and encryption
 * 
 * 		http://en.wikipedia.org/wiki/Diffie_Hellman
 * 
 * 		First, the communication parterns agree on a prime number P, a base
 * 		(primitive root) G as well as on the bit size of the (secret) random
 * 		exponent L. 
 * 
 * 		After that, both partners can choose a secret random number (private key)
 * 		with the given bitsize and calculate the "public key":
 * 
 * 		public_key = (G ^ private_key) mod P
 * 
 * 		Using the public key of the other parter, each one can calculate the
 * 		shared secret key:
 * 
 * 		shared_secret = (partner_public_key ^ private_key) mod P 
 *
 * 
 * Client usage:	client <host> <port> <source account number> <destination
 * account number> <amount>
 * 
 * Courtesy of your friendly neighbourhood WDE assitant.
 * Just remember: We Don't Exist!
 */

import java.math.BigInteger;
import java.net.*;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.io.*;
import java.text.MessageFormat;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

public class DHRougueServer
{
	static int serverPort;
	static String hostname;
	static long sourceAccountNumber;
	static long destAccountNumber;
	static int amount;
	
	
	public static void usage()
	{
		System.err.println("Usage: java SampleClient <host> <port> <source account number> <destination account number> <amount>");
		System.exit(1);
	}
	
	public static void main (String args[])
	{
		Socket s = null;
		String ack;
		
		if (args.length != 5)
			usage();
		
		hostname = args[0];
		serverPort = Integer.parseInt(args[1]);
		sourceAccountNumber = Long.parseLong(args[2]);
		destAccountNumber = Long.parseLong(args[3]);
		amount=Integer.parseInt(args[4]);
		
		
		try
		{
			s = new Socket(hostname, serverPort);
			DataInputStream in = new DataInputStream(s.getInputStream());
			DataOutputStream out = new DataOutputStream(s.getOutputStream());
			
			// receive the ehlo from the server

			// reply with your inetsec credentials and immatriculation number
			
			// check if the server replied with "OK"
			
			// get DH params from server
			
			// generate your public key using the DH params
    		
			// get server's public key
    		
			// send your public key to the server

			// again, check for an "OK" by the server
    		
			// calculate shared encryption key

			// construct a message
			Object[] messageArgs = {
					new String("Destination Acc.no.:"), new Long(destAccountNumber),
					new String("Source Acc.no.     :"), new Long(sourceAccountNumber),
					new String("Amount (in US$)    :"), new Long(amount)
				};

			String message = MessageFormat.format(
				"---------- secure banking wire transfer message ----------\n" +
				"{0} {1,number,000000000000000}\n" +
				"{2} {3,number,000000000000000}\n" +
				"{4} {5,number,000000000000000}\n" +
				"------------------ end of wire transfer ------------------\n",
				messageArgs);
    		
			System.out.println("plaintext message: \n" + message + "\n");


			// encrypt message with shared secret

			// send encrypted message
		}
		catch (Exception e)
		{
			// handle exceptions
		}
		finally
		{
			// close connection
			if(s!=null)
			{
				try
				{
						s.close();
				}
				catch (IOException e)
				{
					System.out.println("close:"+e.getMessage());
				}
			}
		}
	}
}

