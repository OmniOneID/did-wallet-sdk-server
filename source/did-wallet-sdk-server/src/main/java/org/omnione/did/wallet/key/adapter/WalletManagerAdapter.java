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

package org.omnione.did.wallet.key.adapter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.util.HashMap;
import java.util.Map;

import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.keypair.EcKeyPair;
import org.omnione.did.crypto.keypair.KeyPairInterface;
import org.omnione.did.crypto.util.MultiBaseUtils;
import org.omnione.did.wallet.crypto.encryption.EncryptionHelper;
import org.omnione.did.wallet.crypto.sign.SignatureHelper;
import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.file.WalletFile;
import org.omnione.did.wallet.key.data.CryptoKeyPairInfo;
import org.omnione.did.wallet.key.data.CryptoKeyPairInfo.KeyAlgorithmType;
import org.omnione.did.wallet.key.data.KeyElement;
import org.omnione.did.wallet.key.impl.WalletManagerImpl;
import org.omnione.did.wallet.util.logger.WalletLogger;

public class WalletManagerAdapter extends WalletManagerImpl {

	private Map<String, KeyPairInfo> keyPairInfoMap = new HashMap<String, KeyPairInfo>();
	private EncryptionHelper encryptionHelper = new EncryptionHelper();
	private SignatureHelper signatureHelper = new SignatureHelper();
	

	public class KeyPairInfo {
		private String algorithm;
		private KeyPairInterface keyPair;

		public KeyPairInfo(String algorithm, PrivateKey privateKey, PublicKey publicKey) {
			this.algorithm = algorithm;
			this.keyPair = new EcKeyPair(publicKey, privateKey);
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public void setAlgorithm(String algorithm) {
			this.algorithm = algorithm;
		}

		public KeyPairInterface getKeyPair() {
			return keyPair;
		}

		public void setKeyPair(KeyPairInterface keyPair) {
			this.keyPair = keyPair;
		}

	}
	
	public WalletManagerAdapter() {}
	
	public WalletManagerAdapter(String walletfile_pathWithName) throws WalletException {
		super(walletfile_pathWithName);
	}

	

	@Override
	protected byte[] compactSignatureFromHash(String keyId, byte[] hashedSource)
			throws WalletException {
		KeyPairInfo keyPairInfo = getKeyPairInfo(keyId);
		if (keyPairInfo == null) {
			WalletLogger.debug("ERR_CODE_WALLET_KEYID_NOT_EXIST - " + keyId);
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_NOT_EXIST.getCode(), keyId);
		}
		return compactSignatureFromHashedData(keyPairInfo, hashedSource);
	}

	@Override
	public byte[] getSharedSecret(String keyId, String mEncodedCompressedKey) throws WalletException {

		if (!isConnect()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);
		}

		byte[] sharedSecret = null;

		KeyPairInfo keyPairInfo = null;
		keyPairInfo = getKeyPairInfo(keyId);
		if (keyPairInfo == null) {
			WalletLogger.debug("ERR_CODE_WALLET_KEYID_NOT_EXIST - " + keyId);
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_NOT_EXIST.getCode(), keyId);
		}

		sharedSecret = getSharedSecret(keyPairInfo, mEncodedCompressedKey);

		return sharedSecret;
	}

	
	@Override
	protected byte[] getPrivateKeyBytes(CryptoKeyPairInfo cryptoKeyPairInfo) {
		byte[] privateBytes = null;
		if (!(KeyAlgorithmType.SECP256r1.getRawValue().equals(cryptoKeyPairInfo.getAlgorithm())
				|| KeyAlgorithmType.SECP256k1.getRawValue().equals(cryptoKeyPairInfo.getAlgorithm()))) {
		}
		privateBytes = cryptoKeyPairInfo.getPrivateKey().getEncoded();
		return privateBytes;
	}

	
	@Override
	protected byte[] getPublicKeyBytes(CryptoKeyPairInfo cryptoKeyPairInfo) {
		byte[] publicKeyBytes = null;
		if (!(KeyAlgorithmType.SECP256r1.getRawValue().equals(cryptoKeyPairInfo.getAlgorithm())
				|| KeyAlgorithmType.SECP256k1.getRawValue().equals(cryptoKeyPairInfo.getAlgorithm()))) {
		}
		publicKeyBytes = cryptoKeyPairInfo.getPublicKey().getEncoded();
		return publicKeyBytes;
	}
	
	@Override
	protected CryptoKeyPairInfo getCryptoKeyPairInfoFromWalletKeyElement(KeyElement keyElement)
			throws WalletException {
		byte[] encPrivateKeyBytes = new byte[0];
		try {
			encPrivateKeyBytes = MultiBaseUtils.decode(keyElement.getPrivateKey());
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PRIVATE_KEY, e);
		}
		byte[] decPrivateKeyBytes = symDecPrivateKey(encPrivateKeyBytes);

		CryptoKeyPairInfo cryptoKeyPairInfo = null;

		PrivateKey privateKey = encryptionHelper.getPrivateKeyObject(decPrivateKeyBytes);

		byte[] unCompressedPublicKeyBytes = encryptionHelper.getUncompressPublicKey(keyElement.getPublicKey(), keyElement.getAlgorithm());
		PublicKey publicKey = encryptionHelper.getPublicKeyObject(unCompressedPublicKeyBytes);

		cryptoKeyPairInfo = new CryptoKeyPairInfo(keyElement.getKeyId(), keyElement.getAlgorithm(), publicKey,
				privateKey);

		return cryptoKeyPairInfo;
	}	
	
	private KeyPairInfo getKeyPairInfo(String keyId) throws WalletException {
		if (!isConnect()) {
			return null;
		}

		if (WalletFile.ONETIME_LOAD) {
			KeyPairInfo keyInfo = keyPairInfoMap.get(keyId);
			if (keyInfo != null) {
				return keyInfo;
			}
		}

		KeyElement key = getCryptoKeyPairInfo(keyId);
		
	
		if (key == null)
			return null;

		byte[] encPrivateKeyBytes = null;
		try {
			encPrivateKeyBytes = MultiBaseUtils.decode(key.getPrivateKey());
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PRIVATE_KEY, e);
		}
		byte[] decPrivateKeyBytes = symDecPrivateKey(encPrivateKeyBytes);

		
		byte[] compressedPublicKeyBytes = encryptionHelper.getUncompressPublicKey(key.getPublicKey(),key.getAlgorithm());

		KeyPairInfo keyPairInfo = null;

		PrivateKey privateKey = encryptionHelper.getPrivateKeyObject(decPrivateKeyBytes);
		PublicKey publicKey = encryptionHelper.getPublicKeyObject(compressedPublicKeyBytes);

		keyPairInfo = new KeyPairInfo(key.getAlgorithm(), privateKey, publicKey);
		if (WalletFile.ONETIME_LOAD) {
			keyPairInfoMap.put(keyId, keyPairInfo);
		}

		return keyPairInfo;
	}


	private byte[] compactSignatureFromHashedData(KeyPairInfo keyPairInfo, byte[] hashedSource) throws WalletException {

	
		
		byte[] signature = signatureHelper.sign(hashedSource, (ECPrivateKey) keyPairInfo.getKeyPair().getPrivateKey());
		
		byte[] compactSignature = signatureHelper.getCompactSignature(keyPairInfo.getAlgorithm(), signature, (PublicKey)keyPairInfo.getKeyPair().getPublicKey(), hashedSource);
		return compactSignature;
	}
	
	private byte[] getSharedSecret(KeyPairInfo keyPairInfo, String mEncodedCompressedKey) throws WalletException  {
		try {
			return encryptionHelper.getSharedSecret((ECPrivateKey)keyPairInfo.getKeyPair().getPrivateKey(), mEncodedCompressedKey, keyPairInfo.getAlgorithm());
		} catch (WalletException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_GEN_SECRET_FAIL);
		}
	}

	@Override
	protected byte[] getCompressedPublicKeyBytes(CryptoKeyPairInfo CryptoKeyPairInfo) throws WalletException {
		return  encryptionHelper.getCompressedPublicKey(CryptoKeyPairInfo.getPublicKey(), CryptoKeyPairInfo.getAlgorithm());
	}

}
