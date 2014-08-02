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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSASignature {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static byte[] sign (byte[] data, PrivateKey key) {
		try {
			Signature signer = Signature.getInstance("SHA256WithRSA", "BC");
			signer.initSign(key);
			signer.update(data);
			return signer.sign();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return null;
	}

	public static boolean verifySignarture (byte[] data, byte[] signature, PublicKey key) {
		try {
			Signature signer = Signature.getInstance("SHA256WithRSA", "BC");
			signer.initVerify(key);
			signer.update(data);
			return signer.verify(signature);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return false;
	}
}
