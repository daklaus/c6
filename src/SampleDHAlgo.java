import java.math.BigInteger;
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

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;


public class SampleDHAlgo {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		String dhParams = genDhParams();
		
		dhKeyAgreement(dhParams);

	}
	
	private static void dhKeyAgreement(String dhParams) {
		
		// Retrieve the prime, base, and private value for generating the key pair.
		// If the values are encoded as in
		// Generating a Parameter Set for the Diffie-Hellman Key Agreement Algorithm,
		// <http://exampledepot.com/egs/javax.crypto/GenDhParams.html>
		// the following code will extract the values.
		String[] values = dhParams.split(",");
		BigInteger p = new BigInteger(values[0]);
		BigInteger g = new BigInteger(values[1]);
		int l = Integer.parseInt(values[2]);

		try {
		    // Use the values to generate a key pair
		    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
		    DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
		    keyGen.initialize(dhSpec);
		    KeyPair keypair = keyGen.generateKeyPair();

		    // Get the generated public and private keys
		    PrivateKey privateKey = keypair.getPrivate();
		    PublicKey publicKey = keypair.getPublic();

		    // Send the public key bytes to the other party...
		    byte[] publicKeyBytes = publicKey.getEncoded();

		    // Retrieve the public key bytes of the other party
		    //publicKeyBytes = ...;

		    // Convert the public key bytes into a PublicKey object
		    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
		    KeyFactory keyFact = KeyFactory.getInstance("DH");
		    publicKey = keyFact.generatePublic(x509KeySpec);

		    // Prepare to generate the secret key with the private key and public key of the other party
		    KeyAgreement ka = KeyAgreement.getInstance("DH");
		    ka.init(privateKey);
		    ka.doPhase(publicKey, true);

		    // Specify the type of key to generate;
		    // see Listing All Available Symmetric Key Generators
		    // <http://exampledepot.com/egs/javax.crypto/ListKeyGen.html>
		    String algorithm = "DES";

		    // Generate the secret key
		    SecretKey secretKey = ka.generateSecret(algorithm);

		    // Use the secret key to encrypt/decrypt data;
		    // see Encrypting a String with DES
		    // <http://exampledepot.com/egs/javax.crypto/DesString.html>
		} catch (java.security.InvalidKeyException e) {
		} catch (java.security.spec.InvalidKeySpecException e) {
		} catch (java.security.InvalidAlgorithmParameterException e) {
		} catch (java.security.NoSuchAlgorithmException e) {
		}
	}
	
	// Returns a comma-separated string of 3 values.
	// The first number is the prime modulus P.
	// The second number is the base generator G.
	// The third number is bit size of the random exponent L.
	private static String genDhParams() {
	    try {
	        // Create the parameter generator for a 1024-bit DH key pair
	        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
	        paramGen.init(1024);

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
