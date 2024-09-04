/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.crypto.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.util.SignatureUtils;
import org.omnione.did.wallet.crypto.encryption.EncryptionHelper;
import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;

public class SignatureHelper extends AbstractSignatureHelper {
	
	EncryptionHelper encryptionHelper = new EncryptionHelper();

	@Override
	public byte[] sign(byte[] originalHashedMessage, PrivateKey privateKey) throws WalletException {
		try {

			return SignatureUtils.generateEccSignatureFromHashedData(privateKey, originalHashedMessage);
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_SIG_FAIL_SIGN, e);
		}
	}

	@Override
	public void verify(String algorithm, byte[] signData, byte[] publicKeyBytes, byte[] originalHashedMessage)
			throws WalletException {
		try {
			SignatureUtils.verifyCompactSignWithCompressedKey(publicKeyBytes, originalHashedMessage, signData,
					encryptionHelper.getEccCurveTypeFromAlgorithm(algorithm));
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_SIG_VERIFY_SIGN_FAIL, e);
		}
	}
	
	public byte[] getCompactSignature(String algorithm, byte[] signedData, PublicKey publicKey,
			byte[] originalHashedMessage) throws WalletException {
		try {
			return SignatureUtils.convertToCompactSignature(publicKey, originalHashedMessage, signedData, encryptionHelper.getEccCurveTypeFromAlgorithm(algorithm));
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_SIG_COMPRESS_SIGN_FAIL, e);
		}
	}
	
	
}
