
package pl.kotcrab.crypto.test;

import static org.junit.Assert.*;

import org.junit.Test;

import pl.kotcrab.crypto.RSACipher;
import pl.kotcrab.crypto.RSAEncrypter;

public class RSAEncrypterTest {

	@Test
	public void testEncrypter () {
		RSACipher cipher = new RSACipher();
		RSAEncrypter encrypter = new RSAEncrypter(cipher.getPublicKeySpec());

		byte[] data = "qwertyuiopasdfghjklzxcvbnm".getBytes();

		byte[] encrypted = encrypter.encrypt(data);

		assertArrayEquals(data, cipher.decrypt(encrypted));
	}

}
