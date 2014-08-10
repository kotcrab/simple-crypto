package pl.kotcrab.crypto.test;

import static org.junit.Assert.*;

import org.junit.Test;

import pl.kotcrab.crypto.CascadeCipher;
import pl.kotcrab.crypto.EncryptedData;

public class CascadeCipherTest {

	@Test
	public void testCipher () {
		CascadeCipher cipher = new CascadeCipher();
		cipher.initGenerateKeys();
		
		byte[] someData = "qwertyuiopasdfghjklzxcvbnm".getBytes();

		EncryptedData data = cipher.encrypt(someData);
		byte[] decrypted = cipher.decrypt(data);

		assertArrayEquals(someData, decrypted);
	}
	
	@Test
	public void testCipherInitWithKeys () {
		CascadeCipher encrypter = new CascadeCipher();
		CascadeCipher decrypter = new CascadeCipher();
		encrypter.initGenerateKeys();
		decrypter.initWithKeys(encrypter.getKey1(), encrypter.getKey2(), encrypter.getKey3());
		
		byte[] someData = "qwertyuiopasdfghjklzxcvbnm".getBytes();

		EncryptedData data = encrypter.encrypt(someData);
		byte[] decrypted = decrypter.decrypt(data);

		assertArrayEquals(someData, decrypted);
	}

}
