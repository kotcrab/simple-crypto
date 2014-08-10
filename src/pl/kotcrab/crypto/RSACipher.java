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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

//TODO implements SimpleCipher
/** RSA cipher, allows for encrypting and decrypting data.
 * @author Pawel Pastuszak */
public class RSACipher {
	private PublicKey publicKey;
	private PrivateKey privateKey;

	private Cipher decrypter;
	private Cipher encrypter;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/** Constructs {@link RSACipher} with random keys */
	public RSACipher () {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();

			setupCiphers();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	/** Constructs {@link RSACipher} with provided key set
	 * @param keyset key set */
	public RSACipher (RSAKeySet keyset) {
		this(keyset.getPublicKey(), keyset.getPrivatekey());
	}

	/** Constructs {@link RSACipher} with provided keys
	 * @param publicKeySpec public key
	 * @param privateKeySpec private key */
	public RSACipher (X509EncodedKeySpec publicKeySpec, RSAPrivateKeySpec privateKeySpec) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			publicKey = keyFactory.generatePublic(publicKeySpec);
			privateKey = keyFactory.generatePrivate(privateKeySpec);

			setupCiphers();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	private void setupCiphers () throws GeneralSecurityException {
		decrypter = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		decrypter.init(Cipher.DECRYPT_MODE, privateKey);
		encrypter = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		encrypter.init(Cipher.ENCRYPT_MODE, publicKey);
	}

	/** Encrypts some data, if there will be failure during encryption null will be returned, use
	 * {@link RSACipher#encryptSafe(byte[])} if you want to catch exception
	 * @param data data to be encrypted
	 * @return encrypted data */
	public byte[] encrypt (byte[] data) {
		try {
			return encrypter.doFinal(data);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	/** Encrypts some data, if there will be failure during encryption exception will be thrown
	 * @param data data to be encrypted
	 * @return encrypted data */
	public byte[] encryptSafe (byte[] data) throws GeneralSecurityException {
		return encrypter.doFinal(data);
	}

	/** Decrypts some data, if there will be failure during decryption null will be returned, use
	 * {@link RSACipher#decryptSafe(byte[])} if you want to catch exceptions
	 * @param data data to be decrypted
	 * @return decrypted data */
	public byte[] decrypt (byte[] data) {
		try {
			return decrypter.doFinal(data);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	/** Decrypts some data, if there will be failure during decryption exception will be thrown
	 * @param data data to be decrypted
	 * @return decrypted data */
	public byte[] decryptSafe (byte[] data) throws GeneralSecurityException {
		return decrypter.doFinal(data);
	}

	public PrivateKey getPrivateKey () {
		return privateKey;
	}

	public PublicKey getPublicKey () {
		return publicKey;
	}

	public X509EncodedKeySpec getPublicKeySpec () {
		return new X509EncodedKeySpec(publicKey.getEncoded());
	}

	public RSAPrivateKeySpec getPrivateKeySpec () {
		try {
			KeyFactory fact = KeyFactory.getInstance("RSA");
			return fact.getKeySpec(privateKey, RSAPrivateKeySpec.class);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	public RSAKeySet getKeySet () {
		return new RSAKeySet(getPublicKeySpec(), getPrivateKeySpec());
	}

	/** Static method for quick decrypting data without creating objects
	 * @param key private key used for decryption
	 * @param data data to be decrypted
	 * @return decrypted data or null if exceptions occurs */
	public static byte[] decrypt (PrivateKey key, byte[] data) {
		try {
			Cipher decrypter = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
			decrypter.init(Cipher.DECRYPT_MODE, key);
			return decrypter.doFinal(data);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	/** Static method for quick decrypting data without creating objects. If error occurs exception will be thrown
	 * @param key private key used for decryption
	 * @param data data to be decrypted
	 * @return decrypted data */
	public static byte[] decryptSafe (PrivateKey key, byte[] data) throws GeneralSecurityException {
		Cipher decrypter = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		decrypter.init(Cipher.DECRYPT_MODE, key);
		return decrypter.doFinal(data);
	}
}
