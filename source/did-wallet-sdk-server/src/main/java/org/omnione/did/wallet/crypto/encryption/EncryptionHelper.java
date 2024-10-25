/*
 * Copyright 2024 OmniOne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.omnione.did.wallet.crypto.encryption;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.omnione.did.crypto.engines.CipherInfo;
import org.omnione.did.crypto.enums.DidKeyType;
import org.omnione.did.crypto.enums.EccCurveType;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.keypair.KeyPairInterface;
import org.omnione.did.crypto.util.CryptoUtils;
import org.omnione.did.crypto.util.MultiBaseUtils;
import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;

public class EncryptionHelper extends AbstractEncryptionHelper {

//	public enum CurveParamEnum {
//
//		SECP256_R1("Secp256r1", 0), SECP256_K1("Secp256k1", 1);
//
//		CurveParamEnum(String string, int i) {
//		}
//
//	}

	@Override
	public KeyPairInterface generateKeyPair(DidKeyType didKeyType) throws WalletException {
		try {
			return CryptoUtils.generateKeyPair(didKeyType);
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_GEN_KEY_FAIL, e);
		}
	}

	public PrivateKey getPrivateKeyObject(byte[] privateKeyBytes) throws WalletException {
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("EC", "BC");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

			return keyFactory.generatePrivate(privateKeySpec);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PRIVATE_KEY, e);
		}
	}

	public PublicKey getPublicKeyObject(byte[] publicKeyBytes) throws WalletException {
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("EC", "BC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			return keyFactory.generatePublic(publicKeySpec);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PUBLIC_KEY, e);
		}
	}

	public byte[] getSharedSecret(ECPrivateKey privateKey, String mEncodedCompressedKey, String algorithm)
			throws WalletException {
		EccCurveType eccCurveType;
		try {
			eccCurveType = getEccCurveTypeFromAlgorithm(algorithm);
			return CryptoUtils.generateSharedSecret(MultiBaseUtils.decode(mEncodedCompressedKey), privateKey.getEncoded(), eccCurveType);
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_GEN_SECRET_FAIL, e);
		}
	}

	public byte[] encrypt(byte[] source, byte[] key, byte[] iv, String cipherSpec, String padding)
			throws WalletException {
		byte[] ecryptData = null;
		try {
			CipherInfo cipherInfo = new CipherInfo(getSymmetricCipherType(cipherSpec), getSymmetricPaddingType(padding));
			ecryptData = CryptoUtils.encrypt(source, cipherInfo, key, iv);
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_ENCRYPT, e);
		}
		return ecryptData;
	}

	public byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv, String cipherSpec, String padding)
			throws WalletException {
		byte[] decryptedData = null;
		try {
			CipherInfo cipherInfo = new CipherInfo(getSymmetricCipherType(cipherSpec), getSymmetricPaddingType(padding));
			decryptedData = CryptoUtils.decrypt(cipherText, cipherInfo, key, iv);
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_DECRYPT, e);
		}
		return decryptedData;
	}
	
	public byte[] pbkdf2(char[] source, byte[] salt, int iterations, int keySize) throws WalletException {
		try {
			return CryptoUtils.pbkdf2(source, salt, iterations, (keySize + 16) * 8);
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_GEN_KEY_FAIL, e);
		}
	}
	

	public byte[] getCompressedPublicKey(PublicKey publicKey, String algorithm) throws WalletException {
		try {
			byte[] uncompressedPublicKeyBytes = publicKey.getEncoded();
			return CryptoUtils.compressPublicKey(uncompressedPublicKeyBytes, getEccCurveTypeFromAlgorithm(algorithm));
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_COMPRESS_PUBLIC_KEY_FAIL, e);
		}
	}

	public byte[] getUncompressPublicKey(String mEncodedCompressedKey, String algorithm) throws WalletException {
		try {
			byte[] uncompressedPublicKeyBytes = CryptoUtils.unCompressPublicKey(MultiBaseUtils.decode(mEncodedCompressedKey), getEccCurveTypeFromAlgorithm(algorithm));
			return uncompressedPublicKeyBytes;
		} catch (CryptoException  e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_UNCOMPRESS_PUBLIC_KEY_FAIL, e);
		}
	}

}
