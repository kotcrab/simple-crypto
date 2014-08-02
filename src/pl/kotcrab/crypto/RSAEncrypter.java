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
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** RSA encrypter, requires only public key and allows only to encrypt data
 * @author Pawel Pastuszak */
public class RSAEncrypter {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private PublicKey publicKey;
	private Cipher encrypter;

	/** Constructs RSAEncrypter from {@link X509EncodedKeySpec#getEncoded()} encoded with base64
	 * @param publicEncodedBase64 base64 string from {@link X509EncodedKeySpec#getEncoded()} bytes */
	public RSAEncrypter (String publicEncodedBase64) {
		this(new X509EncodedKeySpec(Base64.decodeBase64(publicEncodedBase64)));
	}

	/** Constructs RSAEncrypter from {@link X509EncodedKeySpec#getEncoded()}
	 * @param publicEncoded bytes from {@link X509EncodedKeySpec#getEncoded()} */
	public RSAEncrypter (byte[] publicEncoded) {
		this(new X509EncodedKeySpec(publicEncoded));
	}

	/** Constructs RSAEcnrypted from the key spec itself
	 * @param publicKeySpec key spec */
	public RSAEncrypter (X509EncodedKeySpec publicKeySpec) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");

			publicKey = keyFactory.generatePublic(publicKeySpec);

			setupCiphers();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	private void setupCiphers () throws GeneralSecurityException {
		encrypter = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		encrypter.init(Cipher.ENCRYPT_MODE, publicKey);
	}

	/** Encrypts some data using RSA
	 * @param data data to be encrypted
	 * @return encrypted data or null if exceptions occurred during encryption. Use {@link RSAEncrypter#encryptSafe(byte[])} if you
	 *         want to catch exceptions */
	public byte[] encrypt (byte[] data) {
		try {
			return encrypter.doFinal(data);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	/** Encrypts some data using RSA. Allows to catch exception if error occurres during encryption
	 * @param data data to be encrypted
	 * @return encrypted data */
	public byte[] encryptSafe (byte[] data) throws GeneralSecurityException {
		return encrypter.doFinal(data);
	}
}
