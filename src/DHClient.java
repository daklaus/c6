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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.MessageFormat;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class DHClient {
	private static void usage() {
		System.err
				.println("Usage: java SampleClient <host> <port> <source account number> <destination account number> <amount>");
		System.exit(1);
	}

	public static void main(String args[]) {
		int serverPort;
		String hostname;
		long sourceAccountNumber;
		long destAccountNumber;
		int amount;

		if (args.length != 5)
			usage();

		hostname = args[0];
		serverPort = Integer.parseInt(args[1]);
		sourceAccountNumber = Long.parseLong(args[2]);
		destAccountNumber = Long.parseLong(args[3]);
		amount = Integer.parseInt(args[4]);

		client(hostname, serverPort, sourceAccountNumber, destAccountNumber,
				amount);
	}

	private static void client(String hostname, int serverPort,
			long sourceAccountNumber, long destAccountNumber, int amount) {
		Socket s = null;
		String reply;
		BASE64Decoder base64Dec = new BASE64Decoder();
		BASE64Encoder base64Enc = new BASE64Encoder();

		try {
			try {
				s = new Socket(hostname, serverPort);
				DataInputStream in = new DataInputStream(s.getInputStream());
				DataOutputStream out = new DataOutputStream(s.getOutputStream());

				// receive the ehlo from the server
				reply = in.readUTF();
				if (!reply.equals("EHLO <safest bank customer login>")) {
					System.err.println("Didn't recieve welcome post\n");
					System.exit(1);
				}

				// reply with your inetsec credentials and immatriculation
				// number
				out.writeUTF("EHLO <inetsec046,0926457>");

				// check if the server replied with "OK"
				reply = in.readUTF();
				if (!reply.equals("OK")) {
					System.err.println("Didn't recieve ok reply after login\n");
					System.exit(1);
				}

				// get DH params from server
				reply = in.readUTF();
				String[] values = reply.split(",");
				BigInteger p = new BigInteger(values[0]);
				BigInteger g = new BigInteger(values[1]);
				int l = Integer.parseInt(values[2]);

				// generate your public key using the DH params
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
				DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
				keyGen.initialize(dhSpec);
				KeyPair keypair = keyGen.generateKeyPair();
				PrivateKey privateKey = keypair.getPrivate();
				PublicKey publicKey = keypair.getPublic();

				// get server's public key
				reply = in.readUTF();
				// Convert the public key bytes into a PublicKey object
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
						base64Dec.decodeBuffer(reply));
				KeyFactory keyFact = KeyFactory.getInstance("DH");
				PublicKey publicKeyServer = keyFact.generatePublic(x509KeySpec);

				// send your public key to the server
				out.writeUTF(base64Enc.encode(publicKey.getEncoded()));

				// again, check for an "OK" by the server
				reply = in.readUTF();
				if (!reply.equals("OK")) {
					System.err
							.println("Didn't recieve ok reply after sending public key\n");
					System.exit(1);
				}

				// calculate shared encryption key
				KeyAgreement ka = KeyAgreement.getInstance("DH");
				ka.init(privateKey);
				ka.doPhase(publicKeyServer, true);
				SecretKey secretKey = ka.generateSecret("TripleDES");

				// construct a message
				Object[] messageArgs = { new String("Destination Acc.no.:"),
						new Long(destAccountNumber),
						new String("Source Acc.no.     :"),
						new Long(sourceAccountNumber),
						new String("Amount (in US$)    :"), new Long(amount) };

				String message = MessageFormat
						.format("---------- secure banking wire transfer message ----------\n"
								+ "{0} {1,number,000000000000000}\n"
								+ "{2} {3,number,000000000000000}\n"
								+ "{4} {5,number,000000000000000}\n"
								+ "------------------ end of wire transfer ------------------\n",
								messageArgs);

				System.out.println("plaintext message: \n" + message + "\n");

				// encrypt message with shared secret
				TripleDesEncrypter des = new TripleDesEncrypter(secretKey);
				String encMsg = des.encrypt(message);

				// send encrypted message
				out.writeUTF(encMsg);
				reply = in.readUTF();
				if (!reply.equals("OK")) {
					System.err
							.println("Didn't recieve ok reply after sending transfer\n");
					System.exit(1);
				}

				System.out.println("Transfer successfully sent!");
			} finally {
				// close connection
				if (s != null) {
					s.close();
				}
			}
		} catch (Exception e) {
			// handle exceptions
			e.printStackTrace();
		}
	}
}
