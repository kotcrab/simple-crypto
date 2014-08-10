package pl.kotcrab.crypto.test;

import static org.junit.Assert.*;

import org.junit.Test;

import pl.kotcrab.crypto.RSACipher;

public class RSACipherTest {

	@Test
	public void testCipher () {
		RSACipher cipher = new RSACipher();
		
		byte[] data = "qwertyuiopasdfghjklzxcvbnm".getBytes();

		byte[] encrypted = cipher.encrypt(data);
		assertArrayEquals(data, cipher.decrypt(encrypted));
	}

}
