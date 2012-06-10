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

public class DHRougueServer {

	public static void usage() {
		System.err
				.println("Usage: java DHRogueServer <listen-port> <server> <server-port> <dest-account-number> <amount>");
		System.exit(1);
	}

	public static void main(String args[]) {
		int serverPort;
		int listenPort;
		String server;
		long destAccountNumber;
		int amount;

		if (args.length != 5)
			usage();

		listenPort = Integer.parseInt(args[0]);
		server = args[1];
		serverPort = Integer.parseInt(args[2]);
		destAccountNumber = Long.parseLong(args[3]);
		amount = Integer.parseInt(args[4]);
		
		server(listenPort, server, serverPort, destAccountNumber, amount);
	}

	private static void server(int listenPort, String server, int serverPort,
			long destAccountNumber, int amount) {
		// TODO Auto-generated method stub
		
	}
	

	
	// Returns a comma-separated string of 3 values.
	// The first number is the prime modulus P.
	// The second number is the base generator G.
	// The third number is bit size of the random exponent L.
	private static String genDhParams(int bitLength) {
	    try {
	        // Create the parameter generator for a 1024-bit DH key pair
	        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
	        paramGen.init(bitLength);

	        // Generate the parameters
	        AlgorithmParameters params = paramGen.generateParameters();
	        DHParameterSpec dhSpec
	            = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

	        // Return the three values in a string
	        return ""+dhSpec.getP()+","+dhSpec.getG()+","+dhSpec.getL();
	    } catch (NoSuchAlgorithmException e) {
	    } catch (InvalidParameterSpecException e) {
	    }
	    return null;
	}
	
	
}
