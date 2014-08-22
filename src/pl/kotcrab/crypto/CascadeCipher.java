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

/** Cascade cipher encrypts with 3 different algorithms. Uses {@link SymmetricCipher} as cipher.
 * @author Pawel Pastuszak */
public class CascadeCipher implements SimpleSymmetricCipher {
	private boolean ready;

	private SymmetricCipher cipher1;
	private SymmetricCipher cipher2;
	private SymmetricCipher cipher3;

	private String algorithm1;
	private String algorithm2;
	private String algorithm3;

	/** Constructs {@link CascadeCipher} with default 3 algorithms: AES, Twofish, Serpent. <br>
	 * NOTE: Cipher is not ready yet, {@link CascadeCipher#initGenerateKeys()} or {@link CascadeCipher#initWithKeys()} must be
	 * called to generate random keys or use provided keys. */
	public CascadeCipher () {
		algorithm1 = "AES";
		algorithm2 = "Twofish";
		algorithm3 = "Serpent";
	}

	/** Constructs {@link CascadeCipher} with default 3 provided algorithms. First data will be encrypted using algorithmName1 then
	 * algorithmName2 and algorithmName3<br>
	 * NOTE: Cipher is not ready yet, {@link CascadeCipher#initGenerateKeys()} or {@link CascadeCipher#initWithKeys()} must be
	 * called to generate random keys or use provided keys.
	 * @param algorithmName1
	 * @param algorithmName2
	 * @param algorithmName3 */
	public CascadeCipher (String algorithmName1, String algorithmName2, String algorithmName3) {
		if (algorithmName1 == null || algorithmName2 == null || algorithmName3 == null)
			throw new IllegalArgumentException("Algorithms name cannot be null!");

		this.algorithm1 = algorithmName1;
		this.algorithm2 = algorithmName2;
		this.algorithm3 = algorithmName3;
	}

	/** Initializes cipher with new random keys, after this cipher is ready for use. */
	public void initGenerateKeys () {
		cipher1 = new SymmetricCipher(algorithm1);
		cipher2 = new SymmetricCipher(algorithm2);
		cipher3 = new SymmetricCipher(algorithm3);
		ready = true;
	}

	public void initWithKeys (byte[] argorithmKey1, byte[] argorithmKey2, byte[] argorithmKey3) {
		initWithKeys(argorithmKey1, new EncryptedData(argorithmKey2), new EncryptedData(argorithmKey3));
	}

	/** Initializes cipher with provided keys, after this cipher is ready for use. Keys must be obtained via
	 * {@link CascadeCipher#getKey1()}, {@link CascadeCipher#getKey2()},{@link CascadeCipher#getKey3()} */
	public void initWithKeys (byte[] argorithmKey1, EncryptedData argorithmKey2, EncryptedData argorithmKey3) {
		cipher1 = new SymmetricCipher(algorithm1, argorithmKey1);
		cipher2 = new SymmetricCipher(algorithm2, cipher1.decrypt(argorithmKey2));
		cipher3 = new SymmetricCipher(algorithm3, cipher1.decrypt(cipher2.decrypt(argorithmKey3)));
		ready = true;
	}

	/** Encrypts some data, if there will be failure during encryption null will be returned, use
	 * {@link CascadeCipher#encryptSafe(byte[])} if you want to catch exceptions
	 * @param data data to be encrypted
	 * @return encrypted data */
	@Override
	public EncryptedData encrypt (byte[] data) {
		checkReady();
		return cipher3.encrypt(cipher2.encrypt(cipher1.encrypt(data).getBytes()).getBytes());
	}

	/** Encrypts some data, if there will be failure during encryption exception will be thrown
	 * @param data data to be encrypted
	 * @return encrypted data */
	@Override
	public EncryptedData encryptSafe (byte[] data) throws GeneralSecurityException {
		checkReady();
		return cipher3.encryptSafe(cipher2.encryptSafe(cipher1.encryptSafe(data).getBytes()).getBytes());
	}

	@Override
	public byte[] decrypt (byte[] encryptedDataBytes) {
		return decrypt(new EncryptedData(encryptedDataBytes));

	}

	/** Decrypts some data, if there will be failure during decryption null will be returned, use
	 * {@link CascadeCipher#decryptSafe(byte[])} if you want to catch exceptions
	 * @param data data to be decrypted
	 * @return decrypted data */
	@Override
	public byte[] decrypt (EncryptedData data) {
		checkReady();
		return cipher1.decrypt(new EncryptedData(cipher2.decrypt(new EncryptedData(cipher3.decrypt(data)))));
	}

	@Override
	public byte[] decryptSafe (byte[] encryptedDataBytes) throws GeneralSecurityException {
		return decryptSafe(new EncryptedData(encryptedDataBytes));

	}

	/** Decrypts some data, if there will be failure during decryption exception will be thrown
	 * @param data data to be decrypted
	 * @return decrypted data */
	@Override
	public byte[] decryptSafe (EncryptedData data) throws GeneralSecurityException {
		checkReady();
		return cipher1.decryptSafe(new EncryptedData(cipher2.decryptSafe(new EncryptedData(cipher3.decryptSafe(data)))));
	}

	/** Returns secret key for first algorithm
	 * @return algorithm1 key */
	public byte[] getKey1 () {
		return cipher1.getKeyEncoded();
	}

	/** Returns secret key for second algorithm
	 * @return algorithm2 key encrypted using algoritm1 cipher */
	public EncryptedData getKey2 () {
		return cipher1.encrypt(cipher2.getKeyEncoded());
	}

	/** Returns secret key for third algorithm
	 * @return algorithm3 key encrypted using algoritm1 cipher and algoritm2 cipher */
	public EncryptedData getKey3 () {
		return cipher2.encrypt(cipher1.encrypt(cipher3.getKeyEncoded()).getBytes());
	}

	/** Checks if cipher is ready
	 * @return true if cipher is ready, false otherwise */
	public boolean isReady () {
		return ready;
	}

	private void checkReady () {
		if (!ready) throw new IllegalStateException("CipherCascade not ready!");
	}
}
