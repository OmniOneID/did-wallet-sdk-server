/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.key.impl;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.omnione.did.crypto.enums.DidKeyType;
import org.omnione.did.crypto.enums.MultiBaseType;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.keypair.KeyPairInterface;
import org.omnione.did.crypto.util.CryptoUtils;
import org.omnione.did.crypto.util.MultiBaseUtils;
import org.omnione.did.wallet.crypto.encryption.EncryptionHelper;
import org.omnione.did.wallet.enums.WalletEncryptType;
import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.file.CoreWalletFileHelper;
import org.omnione.did.wallet.file.WalletFile;
import org.omnione.did.wallet.file.WalletFileHandler.WalletFileHelper;
import org.omnione.did.wallet.key.WalletManagerInterface;
import org.omnione.did.wallet.key.data.CryptoKeyPairInfo;
import org.omnione.did.wallet.key.data.CryptoKeyPairInfo.KeyAlgorithmType;
import org.omnione.did.wallet.key.data.EncodingElement;
import org.omnione.did.wallet.key.data.EncryptionInfoElement;
import org.omnione.did.wallet.key.data.HeadElement;
import org.omnione.did.wallet.key.data.KeyElement;
import org.omnione.did.wallet.key.data.SecureKeyInfoElement;
import org.omnione.did.wallet.key.data.Wallet;
import org.omnione.did.wallet.util.Constants;

public abstract class WalletManagerImpl implements WalletManagerInterface {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	protected WalletFileHelper walletFileHelper;
	protected WalletFile walletFile;
	
	private byte[] derivedKeyBytes = null;
	private Wallet cryptoWallet;
	
	EncryptionHelper encryptionHelper = new EncryptionHelper();
	
	public WalletManagerImpl() {
	
	}
	public WalletManagerImpl(String walletFilePath) throws WalletException {
		if (walletFilePath == null || walletFilePath.isEmpty()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_WALLET_FILE);

		}
		
		this.walletFile = new WalletFile(walletFilePath);
		if (!this.walletFile.isExist()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_FILE_LOAD_FAIL);
		}
	}
	
	@Override
	public void create (String walletFilePath, char[] securePassword, WalletEncryptType walletEncryptType) throws WalletException {
		if (walletFilePath == null || walletFilePath.isEmpty()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_WALLET_FILE);

		}

		if (securePassword == null || securePassword.length == 0) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PASSWORD);
		}

		setDefaultEncryptionInfo(walletFilePath, securePassword, walletEncryptType);
		generateSecretPhrase(securePassword);
	}

	private void generateSecretPhrase(char[] securePassword) throws WalletException {
		walletFileHelper = new CoreWalletFileHelper(this.walletFile);

		if (walletFileHelper.isExistSecretPhrase()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_ALREADY_SECRET_PHRASE);
		}

		// generate & save a secretPhrase
		byte[] secretPhraseBytes = walletFileHelper.generateSecretPhrase(securePassword);

		Wallet cryptoWallet = this.walletFile.getData();
		try {
			cryptoWallet.getHead().getSecureKeyInfo().setSecretPhrase(MultiBaseUtils.encode(secretPhraseBytes, MultiBaseType.base58btc));
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_SECRET_PHRASE, e);
		}
		this.walletFile.write(cryptoWallet);

	}

	private void setDefaultEncryptionInfo(String filePath, char[] securePassword, WalletEncryptType walletEncryptType)
			throws WalletException {

		this.walletFile = new WalletFile(filePath);

		if (this.walletFile.isExist()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_ALREADY_FILE);
		}

		Wallet data = new Wallet();
		HeadElement head = new HeadElement();

		String[] splitEncryptType = walletEncryptType.getRawValue().split("-");
		String aesAlgorithm = splitEncryptType.length > 0 ? splitEncryptType[0] : null;
		Integer keySize = splitEncryptType.length > 1 ? Integer.valueOf(splitEncryptType[1]) / 8 : null;
		String mode = splitEncryptType.length > 2 ? splitEncryptType[2] : null;
		String padding = splitEncryptType.length > 3 ? splitEncryptType[3] : null;

		EncryptionInfoElement encryptionInfoElement = new EncryptionInfoElement();
		encryptionInfoElement.setAesAlgorithm(aesAlgorithm);
		encryptionInfoElement.setKeySize(keySize);
		encryptionInfoElement.setMode(mode);
		encryptionInfoElement.setPadding(padding);

		head.setEncryptionInfo(encryptionInfoElement);

		SecureKeyInfoElement secureKeyInfoElement = new SecureKeyInfoElement();
		secureKeyInfoElement.setIterations(2048);
		try {
			secureKeyInfoElement.setSalt(MultiBaseUtils.encode(CryptoUtils.generateSalt(),MultiBaseType.getByCharacter(Constants.keyEncodingType)));
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_GEN_RANDOM_FAIL, e);
		}

		head.setSecureKeyInfo(secureKeyInfoElement);

		head.setEncoding(new EncodingElement());
		data.setHead(head);
		// write and load
		this.walletFile.write(data); 

	}

	@Override
	public boolean isConnect() {

		return (derivedKeyBytes != null ? true : false);
	}

	@Override
	public boolean disConnect() {
		if (derivedKeyBytes != null) {
			Arrays.fill(derivedKeyBytes, (byte) 0x00);
			derivedKeyBytes = null;
		}

		this.walletFile.clearData();

		return true;
	}

	@Override
	public void connect(String filePath, char[] securePassword) throws WalletException {
	
		if (securePassword == null || securePassword.length == 0) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PASSWORD);
		}
		
		this.walletFile = new WalletFile(filePath);
		if (!this.walletFile.isExist()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_NOT_EXISTS_FILE);
		}
		
		this.walletFileHelper = new CoreWalletFileHelper(this.walletFile);
		byte[] result = this.walletFileHelper.authenticate(securePassword);
		
		derivedKeyBytes = new byte[result.length];
		System.arraycopy(result, 0, derivedKeyBytes, 0, result.length);	
		
		this.cryptoWallet = this.walletFile.getData();
		
	}

	private byte[] generateDerivedKey(char[] source, EncryptionInfoElement encryptionInfoElement,
			SecureKeyInfoElement secureKeyInfoElement) throws WalletException {
		byte[] derivedKey = null;

		try {
			derivedKey = encryptionHelper.pbkdf2(source, MultiBaseUtils.decode(secureKeyInfoElement.getSalt()),
					secureKeyInfoElement.getIterations(), encryptionInfoElement.getKeySize());

		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		}

		return derivedKey;

	}

	private String generateSecretPhrase(char[] source, EncryptionInfoElement encryptionInfoElement,
			SecureKeyInfoElement secureKeyInfoElement) throws WalletException {
		String secretPhrase;
		try {

			byte[] derivedKey = generateDerivedKey(source, encryptionInfoElement, secureKeyInfoElement);

			byte[] key = Arrays.copyOfRange(derivedKey, 0, encryptionInfoElement.getKeySize());
			byte[] iv = Arrays.copyOfRange(derivedKey, encryptionInfoElement.getKeySize(), derivedKey.length);

			byte[] data = encryptionHelper.encrypt(Constants.initialPhrase.getBytes(StandardCharsets.UTF_8), key, iv,
					encryptionInfoElement.getSymmetricCipherTypeString(), encryptionInfoElement.getPadding());

			secretPhrase = MultiBaseUtils.encode(data, MultiBaseType.base58btc);

			return secretPhrase;
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		}

	}

	@Override
	public void changePassword(char[] currenSecurePassword, char[] newSecurePassword) throws WalletException {

		if (!walletFile.isExist()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_FILE_LOAD_FAIL);
		}

		Wallet tmpWalletData = null;

		tmpWalletData = walletFile.getData();

		if (tmpWalletData == null) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_FILE_LOAD_FAIL);
		}

		String secretPhrase = tmpWalletData.getHead().getSecureKeyInfo().getSecretPhrase();
		
		if (secretPhrase == null || secretPhrase.length() == 0) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_PASSWORD_NOT_SET);
		}

		if (currenSecurePassword == null || currenSecurePassword.length == 0 || newSecurePassword == null || newSecurePassword.length == 0) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PASSWORD);
		}
	


		// todo. Duplicate logic present. Needs to be fixed
		String recoveredSecretPhrase = null;	
		recoveredSecretPhrase = generateSecretPhrase(currenSecurePassword, tmpWalletData.getHead().getEncryptionInfo()
					, tmpWalletData.getHead().getSecureKeyInfo());
		
		if (recoveredSecretPhrase == null) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DEFAULTKEYSTORE_KEYGEN_FAIL);
		}

		if (!secretPhrase.contentEquals(recoveredSecretPhrase)) { 
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_PASSWORD_NOT_MATCH_WITH_THE_SET_ONE);
		} else if (Arrays.equals(currenSecurePassword, newSecurePassword)) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_PASSWORD_SAME_AS_OLD);
		}

		byte[] proxyByte = generateDerivedKey(currenSecurePassword, tmpWalletData.getHead().getEncryptionInfo(),
				tmpWalletData.getHead().getSecureKeyInfo());

		this.derivedKeyBytes = new byte[proxyByte.length];
		System.arraycopy(proxyByte, 0, this.derivedKeyBytes, 0, proxyByte.length);

		ArrayList<KeyElement> keys = null;  // Decrypted key info
		ArrayList<KeyElement> oldKeys = tmpWalletData.getKeys();
		if (oldKeys != null) {
			keys = decryptPrivateKey(oldKeys);
		}

		String newSecretPhrase = null;

		newSecretPhrase = generateSecretPhrase(newSecurePassword, tmpWalletData.getHead().getEncryptionInfo(),
				tmpWalletData.getHead().getSecureKeyInfo());

		HeadElement head = tmpWalletData.getHead();
		SecureKeyInfoElement secureKeyInfoElement = head.getSecureKeyInfo();
		secureKeyInfoElement.setSecretPhrase(newSecretPhrase);
		head.setSecureKeyInfo(secureKeyInfoElement);
		tmpWalletData.setHead(head);

		Arrays.fill(proxyByte, (byte) 0x00);
		proxyByte = generateDerivedKey(newSecurePassword, tmpWalletData.getHead().getEncryptionInfo(),
				tmpWalletData.getHead().getSecureKeyInfo());


		Arrays.fill(this.derivedKeyBytes, (byte) 0x00);
		this.derivedKeyBytes = null;

		
		this.derivedKeyBytes = new byte[proxyByte.length];
		System.arraycopy(proxyByte, 0, this.derivedKeyBytes, 0, proxyByte.length);
		
		if (keys != null && keys.size() > 0) {
			for (KeyElement element : keys) {

				byte[] decoded = null;
				try {
					decoded = MultiBaseUtils.decode(element.getPrivateKey());
				} catch (Exception e) {
					throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_ENCRYPT);
				}

				String encodedPrivateKey = encrypt(decoded, tmpWalletData.getHead().getEncoding().getKeyEncodingType());

				if (encodedPrivateKey == null) {
					throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_ENCRYPT);
				}
				element.setPrivateKey(encodedPrivateKey);
			}

			tmpWalletData.setKeys(keys);			
			
		}
		
		walletFile.write(tmpWalletData);
	}


	/**
	 * (Key Structure:keys) Remove a CryptoKeyPairInfo by keyId.
	 * 
	 * @param keyId
	 * @return
	 */
	@Override
	public void removeKey(String keyId) throws WalletException {
		if (!isConnect())
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);

		KeyElement key = getCryptoKeyPairInfo(keyId);
		if (key == null)
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_NOT_EXIST);

		Wallet data = walletFile.getData();
		if (data == null) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_FILE_LOAD_FAIL);
		}

		boolean isChanged = false;

		ArrayList<KeyElement> keys = data.getKeys();
		for (KeyElement k : keys) {
			if (k.getKeyId().equals(keyId)) {
				if (keys.remove(k)) {
					isChanged = true;
					break;
				}
			}
		}

		if (isChanged == true) {
			data.setKeys(keys);
			walletFile.write(data);
		}

	}

	/**
	 * (Key Structure:keys) Add a CryptoKeyPairInfo.
	 * 
	 * @param key
	 * @return
	 * @throws WalletException
	 */
	@Override
	public void addKey(CryptoKeyPairInfo key) throws WalletException {
		if (!isConnect())
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);

		if (key == null) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_IWKEY_IS_NULL);
		}

		// todo algorithm checked
//		if (key.getAlg() != ALGORITHM_TYPE.ALGORITHM_SECP256k1.getValue()) {
//			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_ALGORITHM_TYPE);
//		}

		if (key.getKeyId().equals("") || key.getKeyId() == null) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_EMPTY_NAME);
		}

		if (!key.getKeyId().matches("^[0-9a-zA-Z.]+$"))
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_KEYID_NAME);

//		// privateKey, publicKey check
//		if (key.getPrivateKey().getEncoded().length != 32) {
//			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PRIVATE_KEY);
//		}

//		if (key.getPublicKey().getEncoded().length != 33) {
//			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PUBLIC_KEY);
//		}

		if (walletFile.getData() != null && walletFile.getData().getKeys() != null) {
			ArrayList<KeyElement> keyEles = walletFile.getData().getKeys();
			for (KeyElement keyEle : keyEles) {
				if (keyEle.getKeyId().equals(key.getKeyId())) {

					throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_ALREADY_EXIST);
				}
			}
		}

		Wallet data = walletFile.getData();
		ArrayList<KeyElement> keys = data.getKeys();

		if (keys == null) {
			keys = new ArrayList<KeyElement>();
		}
		keys.add(convertToWalletKeyElement(key));
		data.setKeys(keys);

		walletFile.write(data);
	}

	/**
	 * (Key Structure:keys) Generate Random CryptoKeyPairInfo.
	 * 
	 * @param keyId
	 * @param keyAlgorithmType
	 * @return
	 * @throws WalletException
	 */
	@Override	
	public void generateRandomKey(String keyId, KeyAlgorithmType keyAlgorithmType) throws WalletException {
		if (!isConnect()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);
		}

		if (isExistKey(keyId)) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_ALREADY_EXIST);
		}

		KeyPairInterface keyParir = null;

		keyParir = encryptionHelper.generateKeyPair(convertDidKeyType(keyAlgorithmType));

		if (keyId.equals("")) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_EMPTY_NAME);
		}

		CryptoKeyPairInfo cryptoKeyPairInfo = new CryptoKeyPairInfo(keyId, keyAlgorithmType.toString(),
				(PublicKey) keyParir.getPublicKey(), (PrivateKey) keyParir.getPrivateKey());

		addKey(cryptoKeyPairInfo);
	}
	

	public DidKeyType convertDidKeyType(KeyAlgorithmType keyAlgorithmType) throws WalletException {

		if (KeyAlgorithmType.SECP256r1.equals(keyAlgorithmType)) {
			return DidKeyType.SECP256R1_VERIFICATION_KEY_2018;
		} else if (KeyAlgorithmType.SECP256k1.equals(keyAlgorithmType)) {
			return DidKeyType.SECP256K1_VERIFICATION_KEY_2018;
		} else if (KeyAlgorithmType.RSA2048.equals(keyAlgorithmType)) {
			return DidKeyType.RSA_VERIFICATION_KEY_2018;
		} else {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_ALGORITHM_TYPE);
		}

	}
	
	/**
	 * (Key Structure:keys) Get a CryptoKeyPairInfo by keyId.
	 * 
	 * @param keyId
	 * @return
	 */
	@Override
	public String getPublicKey(String keyId) throws WalletException {
		KeyElement key = getCryptoKeyPairInfo(keyId);
		if (key == null)
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_NOT_EXIST);

		return key.getPublicKey();
	}
	
	@Override
	public KeyElement getKeyElement(String keyId) throws WalletException {
		KeyElement key = getCryptoKeyPairInfo(keyId);
		if (key == null)
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_NOT_EXIST);

		return key;
	}
	

	/**
	 * (Key Structure:keys) Get a CryptoKeyPairInfo by keyId.
	 * 
	 * @param keyId
	 * @return
	 * @throws WalletException
	 */
	private CryptoKeyPairInfo getWalletKeyElement(String keyId) throws WalletException {
		if (!isConnect())
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);

		KeyElement key = getCryptoKeyPairInfo(keyId);
		if (key == null)
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_KEYID_NOT_EXIST);

		return this.getCryptoKeyPairInfoFromWalletKeyElement(key);
	}
	
	@Override
	public String getKeyAlgorithm(String keyId) throws WalletException {
		CryptoKeyPairInfo key = null;
		key = getWalletKeyElement(keyId);
		return key.getAlgorithm();

	}

	@Override
	public boolean isExistKey(String keyId) throws WalletException {
	
		if (!isConnect()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);
		}
		
		if( keyId == null || keyId.isEmpty()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);
		}

		if (getKeyIdList() != null && getKeyIdList().contains(keyId)) {
			return true;
		}

		return false;
	}

	@Override
	public List<String> getKeyIdList() throws WalletException {
		List<KeyElement> keyEles = getCryptoKeyPairInfoList();
		if (keyEles == null || keyEles.size() == 0) {
			return null;
		}

		List<String> keyIds = new ArrayList<String>();
		for (KeyElement keyId : keyEles) {
			keyIds.add(keyId.getKeyId());
		}

		return keyIds;
	}
	
	@Override
	public byte[] generateCompactSignatureFromHash(String keyId, byte[] source) throws WalletException {
		if (!isConnect())
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);

		return compactSignatureFromHash(keyId, source);
	}

	@Override
	public void removeAllKeys() throws WalletException {
		if (!isConnect()) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_DISCONNECT);
		}

		Wallet data = walletFile.getData();
		if (data == null) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_FILE_LOAD_FAIL);
		}

		ArrayList<KeyElement> keys = data.getKeys();

		if (keys != null && keys.size() > 0) {
			data.setKeys(null);
			walletFile.write(data);
		}
	}

//	private boolean isNeedGenerateProxyKey() throws WalletException {
//		// if helper is android and the keyfile is not set a proxykey yet,
//		// return true
//		WalletData data = keyFile.getData();
//		if (data == null) {
//			genKeyFile();
//		}
//		String pk = keyFile.getData().getHead().getProxyKey();
//		return pk == null ? true : false;
//	}


	private byte[] symEncPrivateKey(byte[] privateKey) throws WalletException {
		return symEncPrivateKey(privateKey, derivedKeyBytes);
	}

	private byte[] symEncPrivateKey(byte[] privateKey, byte[] derivedKey) throws WalletException {

		HeadElement head = this.cryptoWallet.getHead();
		EncryptionInfoElement encryptionInfo = head.getEncryptionInfo();

		byte[] key = Arrays.copyOfRange(derivedKey, 0, encryptionInfo.getKeySize());
		byte[] iv = Arrays.copyOfRange(derivedKey, encryptionInfo.getKeySize(), derivedKey.length);

		byte[] data = encryptionHelper.encrypt(privateKey, key, iv, encryptionInfo.getSymmetricCipherTypeString(),
				encryptionInfo.getPadding());

		return data;

	}

	protected byte[] symDecPrivateKey(byte[] encPrivateKey) throws WalletException {
		return symDecPrivateKey(encPrivateKey, derivedKeyBytes);
	}

	protected byte[] symDecPrivateKey(byte[] encPrivateKey, byte[] derivedKey) throws WalletException {

		HeadElement head = this.cryptoWallet.getHead();
		EncryptionInfoElement encryptionInfo = head.getEncryptionInfo();

		byte[] key = Arrays.copyOfRange(derivedKey, 0, encryptionInfo.getKeySize());
		byte[] iv = Arrays.copyOfRange(derivedKey, encryptionInfo.getKeySize(), derivedKey.length);

		byte[] data = encryptionHelper.decrypt(encPrivateKey, key, iv, encryptionInfo.getSymmetricCipherTypeString(),
				encryptionInfo.getPadding());

		return data;

	}

	protected KeyElement getCryptoKeyPairInfo(String keyId) throws WalletException {
		Wallet data = walletFile.getData();
		
		ArrayList<KeyElement> keys = data.getKeys();
		if (keys == null)
			return null;

		for (KeyElement key : keys) {
			if (key.getKeyId().equals(keyId)) {
				return key;
			}
		}

		return null;
	}

	private List<KeyElement> getCryptoKeyPairInfoList() throws WalletException {
		Wallet data = walletFile.getData();
		if (data == null)
			return null;

		ArrayList<KeyElement> keys = data.getKeys();
		return keys;
	}


	protected KeyElement convertToWalletKeyElement(CryptoKeyPairInfo cryptoKeyPairInfo) throws WalletException {
		KeyElement keyElement = new KeyElement();
		keyElement.setKeyId(cryptoKeyPairInfo.getKeyId());
		keyElement.setAlgorithm(cryptoKeyPairInfo.getAlgorithm());
		Wallet cryptoWallet = walletFile.getData();

		String encodingType = cryptoWallet.getHead().getEncoding().getKeyEncodingType();
		String encPriKey_encodedBase58 = encrypt(getPrivateKeyBytes(cryptoKeyPairInfo), encodingType);

		keyElement.setPrivateKey(encPriKey_encodedBase58);
		// publicKey  to  compressedPublicKey
		try {
			keyElement.setPublicKey(MultiBaseUtils.encode(getCompressedPublicKeyBytes(cryptoKeyPairInfo), MultiBaseType.base58btc));
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PUBLIC_KEY, e);
		}
		//	System.out.println("Base58! = " + MultiBaseUtils.encode(getPublicKeyBytes(cryptoKeyPairInfo), MultiBaseType.base58btc));
	//	System.out.println("HEX! = " + MultiBaseUtils.encode(getPublicKeyBytes(cryptoKeyPairInfo), MultiBaseType.base16));
		return keyElement;
	}
	
	protected String encrypt(byte[] toBeEncoded, String encodingType) throws WalletException {

		// private key
		byte[] encrypted = symEncPrivateKey(toBeEncoded);

		try {
			return MultiBaseUtils.encode(encrypted, MultiBaseType.getByCharacter(encodingType));
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_ENCRYPT, e);
		}
		// return encodeByte(encrypted, encodingType);
	}

	protected byte[] decrypt(String toBeDecoded) throws WalletException {

		byte[] decoded = new byte[0];
		try {
			decoded = MultiBaseUtils.decode(toBeDecoded);
		} catch (CryptoException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_DECRYPT, e);
		}
		byte[] decrypted = symDecPrivateKey(decoded);
		return decrypted;
	}


	private ArrayList<KeyElement> decryptPrivateKey(ArrayList<KeyElement> keys) throws WalletException {
		for (KeyElement element : keys) {
			String pKeyString = element.getPrivateKey();

			byte[] valueByte = null;
			valueByte = decrypt(pKeyString);
			if (valueByte == null) {
				throw new WalletException(WalletErrorCode.ERR_CODE_CRYPTO_DECRYPT);
			}

			try {
				element.setPrivateKey(MultiBaseUtils.encode(valueByte, MultiBaseType.base58btc));
			} catch (CryptoException e) {
				throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_PRIVATE_KEY, e);
			}
		}
		return keys;
	}

	protected abstract CryptoKeyPairInfo getCryptoKeyPairInfoFromWalletKeyElement(KeyElement iwWalletKeyElement) throws WalletException;

	protected abstract byte[] getPrivateKeyBytes(CryptoKeyPairInfo cryptoKeyPairInfo);

	protected abstract byte[] getCompressedPublicKeyBytes(CryptoKeyPairInfo CryptoKeyPairInfo) throws WalletException;
	
	protected abstract byte[] getPublicKeyBytes(CryptoKeyPairInfo cryptoKeyPairInfo);

	protected abstract byte[] compactSignatureFromHash(String keyId, byte[] hashedSource) throws WalletException;

	
}