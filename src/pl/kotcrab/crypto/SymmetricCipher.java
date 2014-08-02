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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Easy to use symmetric cipher
 * @author Pawel Pastuszak */
public class SymmetricCipher {

	private static final String MODE = "/CBC/PKCS5Padding";
	private static final String PROVIDER = "BC";

	private String algorithm;
	private SecretKey key;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/** Constructs symmetric cipher for provided algorithm name with random keys
	 * @param algorithmName name of algorithm for this cipher */
	public SymmetricCipher (String algorithmName) {
		init(algorithmName);

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(algorithmName, PROVIDER);
			keyGen.init(256);
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
	}

	/** Constructs symmetric cipher for provided algorithm name with provided key
	 * @param algorithmName name of algorithm for this cipher
	 * @param key key for this cipher */
	public SymmetricCipher (String algorithmName, byte[] key) {
		init(algorithmName);

		this.key = new SecretKeySpec(key, algorithmName);
	}

	/** Constructs symmetric cipher for provided algorithm name with provided key
	 * @param algorithmName name of algorithm for this cipher
	 * @param key key for this cipher */
	public SymmetricCipher (String algorithmName, SecretKeySpec key) {
		init(algorithmName);

		this.key = key;
	}

	private void init (String algorithmName) {
		this.algorithm = algorithmName + MODE;
	}

	public void setKey (SecretKey key) {
		this.key = key;
	}

	public byte[] getKeyEncoded () {
		return key.getEncoded();
	}

	/** Encrypts some data, if there will be failure during encryption null will be returned, use
	 * {@link CascadeCipher#encryptSafe(byte[])} if you want to catch exception
	 * @param data data to be encrypted
	 * @return encrypted data */
	public EncryptedData encrypt (byte[] data) {
		try {
			return encryptSafe(data);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	/** Encrypts some data, if there will be failure during encryption exception will be thrown
	 * @param data data to be encrypted
	 * @return encrypted data */
	public EncryptedData encryptSafe (byte[] data) throws GeneralSecurityException {
		EncryptedData msg = new EncryptedData();
		msg.iv = CryptoUtils.getRandomBytes16();

		Cipher encrypter = Cipher.getInstance(algorithm, PROVIDER);
		encrypter.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(msg.iv));
		msg.encrypted = encrypter.doFinal(data);
		return msg;
	}

	/** Decrypts some data, if there will be failure during decryption null will be returned, use
	 * {@link SymmetricCipher#decryptSafe(byte[])} if you want to catch exceptions
	 * @param encryptedDataBytes data to be decrypted
	 * @return decrypted data */
	public byte[] decrypt (byte[] encryptedDataBytes) {
		return decrypt(new EncryptedData(encryptedDataBytes));
	}

	/** Decrypts some data, if there will be failure during decryption null will be returned, use
	 * {@link SymmetricCipher#decryptSafe(byte[])} if you want to catch exceptions
	 * @param data data to be decrypted
	 * @return decrypted data */
	public byte[] decrypt (EncryptedData data) {
		try {
			return decryptSafe(data);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	/** Decrypts some data, if there will be failure during decryption exception will be thrown
	 * @param encryptedDataBytes data to be decrypted
	 * @return decrypted data */
	public byte[] decryptSafe (byte[] encryptedDataBytes) throws GeneralSecurityException {
		return decryptSafe(new EncryptedData(encryptedDataBytes));
	}

	/** Decrypts some data, if there will be failure during decryption exception will be thrown
	 * @param data data to be decrypted
	 * @return decrypted data */
	public byte[] decryptSafe (EncryptedData data) throws GeneralSecurityException {
		Cipher decrypter = Cipher.getInstance(algorithm, PROVIDER);
		decrypter.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(data.iv));
		return decrypter.doFinal(data.encrypted);

	}

}
