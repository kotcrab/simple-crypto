/*******************************************************************************
 * Copyright 2014 Pawel Pastuszak
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package pl.kotcrab.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Provides various cryptographic methods.
 * @author Pawel Pastuszak */
public class CryptoUtils {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static SecureRandom random;

	private static final int MAX_BYTES_BEFORE_RESEED = 100000;
	private static int bytesTaken = 0;

	static {
		random = getSecureRandom();
	}

	/** Constructs and returns secure random. Algorithm depends on operating system, on Windows SHA1PRNG from Sun will be used and on
	 * Unix and Mac systems NativePRNG will be used.
	 * @return SecureRandom instance */
	public static SecureRandom getSecureRandom () {
		try {
			if (OSDetector.isUnix() || OSDetector.isMac())
				return SecureRandom.getInstance("NativePRNG", "SUN");
			else
				return SecureRandom.getInstance("SHA1PRNG", "SUN");
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	private static void reseedRandomIfNeeded () {
		if (bytesTaken >= MAX_BYTES_BEFORE_RESEED) {
			random = getSecureRandom();
			bytesTaken = 0;
		}
	}

	/** Generates random 16 bytes
	 * @return random 16 bytes */
	public static byte[] getRandomBytes16 () {
		bytesTaken += 16;
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		reseedRandomIfNeeded();
		return salt;
	}

	/** Generates PublicKey from encoded bytes of X509EncodedKeySpec. Bytes must be in Base64 string.
	 * @param base64 Key from encoded bytes of {@link X509EncodedKeySpec#getEncoded()}. Encoded in Base64 string.
	 * @return created public key */
	public static PublicKey getRSAPublicKeyFromString64 (String base64) {
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(base64));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
			return keyFactory.generatePublic(keySpec);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	/** Generates AES key from provided password and salt. Used algorithm is PBKDF2WithHmacSHA1.
	 * @param password password in char array, using {@link CryptoUtils#fillZeros(char[])} is recommend after generating key
	 * @param salt salt for this key
	 * @return SecretKeySpec */
	public static SecretKeySpec getAESKeyFromPassword (char[] password, byte[] salt) {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
			return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	/** Returns AES SecretKey from provided encoded bytes.
	 * 
	 * @param encoded encoded bytes of SecretKeySpec
	 * @return SecretKey */
	public static SecretKey getAESKeyFromEncoded (byte[] encoded) {
		return new SecretKeySpec(encoded, 0, encoded.length, "AES");
	}

	/** Generates random AES key
	 * @return random AES key */
	public static SecretKey getAESRandomKey () {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
			keyGen.init(256);
			return keyGen.generateKey();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}

		return null;
	}

	/** Fills zeros in provided char array, useful for clearing arrays with passwords
	 * @param array array to be cleared */
	public static void fillZeros (char[] array) {
		for (int i = 0; i < array.length; i++)
			array[i] = 0;
	}
}
