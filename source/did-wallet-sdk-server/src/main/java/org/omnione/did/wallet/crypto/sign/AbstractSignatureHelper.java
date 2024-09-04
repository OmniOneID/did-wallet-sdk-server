/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.crypto.sign;

import java.security.PrivateKey;

import org.omnione.did.crypto.enums.DidKeyType;
import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.key.data.CryptoKeyPairInfo.KeyAlgorithmType;

public abstract class AbstractSignatureHelper {

	abstract public byte[] sign(byte[] originalHashedMessage, PrivateKey privateKey) throws WalletException;

	abstract public void verify(String algorithm, byte[] sign, byte[] publicKey, byte[] signedMessage) throws WalletException;
	
	public DidKeyType convertDidKeyType(String keyAlgorithm) throws WalletException {
		
		if(keyAlgorithm == null || keyAlgorithm.isEmpty()) {
			 throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_ALGORITHM_TYPE);
		}
		
	    if (keyAlgorithm.equals(KeyAlgorithmType.SECP256k1.getRawValue())) {
            return DidKeyType.SECP256K1_VERIFICATION_KEY_2018;
        } else if (keyAlgorithm.equals(KeyAlgorithmType.SECP256r1.getRawValue())) {
            return DidKeyType.SECP256R1_VERIFICATION_KEY_2018;
        } else if (keyAlgorithm.equals(KeyAlgorithmType.RSA2048.getRawValue())) {
            return DidKeyType.RSA_VERIFICATION_KEY_2018;
        } else {
            throw new IllegalArgumentException("Invalid key algorithm: " + keyAlgorithm);
        }
	}

}
