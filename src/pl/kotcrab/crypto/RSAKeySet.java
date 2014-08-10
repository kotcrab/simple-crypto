
package pl.kotcrab.crypto;

import java.math.BigInteger;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;

/** Kryo serializable keys for RSA cipher.
 * 
 * @author Pawel Pastuszak */
public class RSAKeySet {
	private byte[] publicEnocoded;
	private BigInteger privateExponent;
	private BigInteger modulus;

	/** No argument constructor for kryo. */
	@Deprecated
	public RSAKeySet () {

	}

	public RSAKeySet (X509EncodedKeySpec publicKey, RSAPrivateKeySpec privateKey) {
		publicEnocoded = publicKey.getEncoded();
		privateExponent = privateKey.getPrivateExponent();
		modulus = privateKey.getModulus();
	}

	public X509EncodedKeySpec getPublicKey () {
		return new X509EncodedKeySpec(publicEnocoded);
	}

	public RSAPrivateKeySpec getPrivatekey () {
		return new RSAPrivateKeySpec(modulus, privateExponent);
	}
}
