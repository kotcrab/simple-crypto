
package pl.kotcrab.crypto.test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import pl.kotcrab.crypto.RSACipher;
import pl.kotcrab.crypto.RSASignature;

public class RSASignerTest {

	@Test
	public void testSignAndVerify () {
		RSACipher keys = new RSACipher();

		byte[] dataToSign = "qwertyuiopasdfghjklzxcvbnm".getBytes();

		byte[] signature = RSASignature.sign(dataToSign, keys.getPrivateKey());
		
		assertTrue(RSASignature.verifySignarture(dataToSign, signature, keys.getPublicKey()));
	}
	
	@Test
	public void testSignAndVerifyWithFalseKey () {
		RSACipher keys = new RSACipher();
		RSACipher difrentKeys = new RSACipher();

		byte[] dataToSign = "qwertyuiopasdfghjklzxcvbnm".getBytes();

		byte[] signature = RSASignature.sign(dataToSign, keys.getPrivateKey());
		
		assertFalse(RSASignature.verifySignarture(dataToSign, signature, difrentKeys.getPublicKey()));
	}

}
