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

import org.apache.commons.codec.binary.Base64;

/** Storage for encrypted data via symmetric cipher. Data and IV are stored.
 * @author Pawel Pastuszak */
public class EncryptedData {
	public byte[] encrypted;
	public byte[] iv;

	public EncryptedData () {
	}

	public EncryptedData (byte[] data) {
		init(new String(data));
	}

	public EncryptedData (String data) {
		init(data);
	}

	private void init (String data) {
		String[] splited = data.split("-");
		iv = Base64.decodeBase64(splited[0]);
		encrypted = Base64.decodeBase64(splited[1]);
	}

	@Override
	public String toString () {
		return Base64.encodeBase64String(iv) + "-" + Base64.encodeBase64String(encrypted);
	}

	public byte[] getBytes () {
		return toString().getBytes();
	}

}
