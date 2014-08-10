
package pl.kotcrab.crypto;

import java.security.GeneralSecurityException;

public interface SimpleCipher {
	public EncryptedData encrypt (byte[] data);

	public EncryptedData encryptSafe (byte[] data) throws GeneralSecurityException;

	public byte[] decrypt (byte[] encryptedDataBytes);

	public byte[] decrypt (EncryptedData data);

	public byte[] decryptSafe (byte[] encryptedDataBytes) throws GeneralSecurityException;

	public byte[] decryptSafe (EncryptedData data) throws GeneralSecurityException;
}
