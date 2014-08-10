
package pl.kotcrab.crypto.test;

import static org.junit.Assert.*;

import org.junit.Test;

import pl.kotcrab.crypto.EncryptedData;
import pl.kotcrab.crypto.SymmetricCipher;

public class SymmetricCipherTest {

	@Test
	public void testAES () {
		testEncryption("AES");
	}

	@Test
	public void testSerpent () {
		testEncryption("Serpent");
	}

	@Test
	public void testTwofish () {
		testEncryption("Twofish");
	}

	private void testEncryption (String algorithmName) {
		SymmetricCipher cipher = new SymmetricCipher(algorithmName);

		byte[] someData = "qwertyuiopasdfghjklzxcvbnm".getBytes();

		EncryptedData data = cipher.encrypt(someData);
		byte[] decrypted = cipher.decrypt(data);

		assertArrayEquals(someData, decrypted);
	}

}
