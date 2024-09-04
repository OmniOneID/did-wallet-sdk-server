/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.file;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.util.MultiBaseUtils;
import org.omnione.did.wallet.crypto.encryption.EncryptionHelper;
import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.file.WalletFileHandler.WalletFileHelper;
import org.omnione.did.wallet.key.data.EncryptionInfoElement;
import org.omnione.did.wallet.key.data.HeadElement;
import org.omnione.did.wallet.key.data.SecureKeyInfoElement;
import org.omnione.did.wallet.util.Constants;

/**
 * The CoreWalletFileHelper class implements the WalletFileHelper interface.
 * It also provides functionality for generating and authenticating the SecretPhrase of a wallet file.
 */
public class CoreWalletFileHelper implements WalletFileHelper {

	private WalletFile walletFile;
	private boolean isSecretPhrase;
	private EncryptionHelper encryptionHelper = new EncryptionHelper();

	/**
	 * CoreWalletFileHelper constructor.
	 *
	 * @param walletFile wallet file object
	 * @throws WalletException Occurs when wallet data cannot be loaded
	 */
	public CoreWalletFileHelper(WalletFile walletFile) throws WalletException {
		this.walletFile = walletFile;
		this.isSecretPhrase = this.walletFile.getData().getHead().getSecureKeyInfo().getSecretPhrase() != null;

	}

    /**
     * Returns whether the SecretPhrase exists.
     * @return SecretPhrase existence
     */
	@Override
	public boolean isExistSecretPhrase() {

		return this.isSecretPhrase;
	}

	 /**
     * Create a SecretPhrase with password.
     *
     * @param securePassword password
     * @return Byte array of the generated SecretPhrase
     * @throws WalletException If an error occurs during SecretPhrase generation
     */
	@Override
	public byte[] generateSecretPhrase(char[] securePassword) throws WalletException {
		HeadElement head = this.walletFile.getData().getHead();
		SecureKeyInfoElement secureKeyInfo = head.getSecureKeyInfo();
		EncryptionInfoElement encryptionInfo = head.getEncryptionInfo();

		byte[] data = null;
		try {

			byte[] derivedKey = encryptionHelper.pbkdf2(securePassword, MultiBaseUtils.decode(secureKeyInfo.getSalt()),
					secureKeyInfo.getIterations(), encryptionInfo.getKeySize());

			byte[] key = Arrays.copyOfRange(derivedKey, 0, encryptionInfo.getKeySize());
			byte[] iv = Arrays.copyOfRange(derivedKey, encryptionInfo.getKeySize(), derivedKey.length);

			data = encryptionHelper.encrypt(Constants.initialPhrase.getBytes(StandardCharsets.UTF_8), key, iv,
					encryptionInfo.getSymmetricCipherTypeString(), encryptionInfo.getPadding());

			return data;
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		}

	}


    /**
     *  Use securePassword to authenticate the SecretPhrase.
     *
     * @param securePassword password
     * @return derivedKey Byte array of the generated SecretPhrase
     * @throws WalletException Fires when securePassword authentication fails
     */
	@Override
	public byte[] authenticate(char[] securePassword) throws WalletException {

		byte[] derivedKey = null;
		HeadElement head = this.walletFile.getData().getHead();
		SecureKeyInfoElement secureKeyInfo = head.getSecureKeyInfo();
		EncryptionInfoElement encryptionInfo = head.getEncryptionInfo();
		
		byte[] data = null;
		try {

			derivedKey = encryptionHelper.pbkdf2(securePassword, MultiBaseUtils.decode(secureKeyInfo.getSalt()),
					secureKeyInfo.getIterations(), encryptionInfo.getKeySize());

			byte[] key = Arrays.copyOfRange(derivedKey, 0, encryptionInfo.getKeySize());
			byte[] iv = Arrays.copyOfRange(derivedKey, encryptionInfo.getKeySize(), derivedKey.length);

			data = encryptionHelper.decrypt(MultiBaseUtils.decode(secureKeyInfo.getSecretPhrase()), key, iv,
					encryptionInfo.getSymmetricCipherTypeString(), encryptionInfo.getPadding());

			if (!Arrays.equals(data, Constants.initialPhrase.getBytes(StandardCharsets.UTF_8))) {
				throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DEFAULTKEYSTORE_AUTHENTICATE_FAIL.getCode());
			}

			Arrays.fill(data, (byte) 0x00);

			return derivedKey;

		} catch (Exception e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DEFAULTKEYSTORE_AUTHENTICATE_FAIL.getCode(),
					e.getMessage());
		}

	}
}
