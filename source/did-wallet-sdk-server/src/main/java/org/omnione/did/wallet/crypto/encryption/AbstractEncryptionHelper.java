/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.crypto.encryption;

import org.omnione.did.crypto.enums.DidKeyType;
import org.omnione.did.crypto.enums.EccCurveType;
import org.omnione.did.crypto.enums.SymmetricCipherType;
import org.omnione.did.crypto.enums.SymmetricPaddingType;
import org.omnione.did.crypto.keypair.KeyPairInterface;
import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;

public abstract class AbstractEncryptionHelper {
		
	abstract KeyPairInterface generateKeyPair(DidKeyType didKeyType) throws WalletException;
	
	abstract public byte[] encrypt(byte[] source, byte[] key, byte[] iv, String cipherSpec, String padding) throws WalletException;
	
	abstract public byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv, String cipherSpec, String padding) throws WalletException;
	
	protected SymmetricCipherType getSymmetricCipherType(String cipherSpec) {
		SymmetricCipherType symCipherType = SymmetricCipherType.fromString(cipherSpec);
		return symCipherType;
	}

	protected SymmetricPaddingType getSymmetricPaddingType(String padding) {
		SymmetricPaddingType symPaddingType = SymmetricPaddingType.fromString(padding);
		return symPaddingType;
	}
	
	public EccCurveType getEccCurveTypeFromAlgorithm(String algorithm) throws WalletException {
		EccCurveType eccCurveType;

		if (EccCurveType.Secp256r1.getCurveName().equals(algorithm)) {
			eccCurveType = EccCurveType.Secp256r1;
		} else if (EccCurveType.Secp256k1.getCurveName().equals(algorithm)) {
			eccCurveType = EccCurveType.Secp256k1;
		} else {
			System.out.println("algorithm:" + algorithm);
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_ALGORITHM_TYPE);
		}
		return eccCurveType;
	}

}
