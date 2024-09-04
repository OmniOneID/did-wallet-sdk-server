/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.key;
import java.util.List;

import org.omnione.did.wallet.enums.WalletEncryptType;
import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.key.data.CryptoKeyPairInfo;
import org.omnione.did.wallet.key.data.CryptoKeyPairInfo.KeyAlgorithmType;
import org.omnione.did.wallet.key.data.KeyElement;

public interface WalletManagerInterface {

	 /**
     * Creates a new wallet file with the specified parameters.
     *
     * @param walletFilePath   The path where the wallet file will be created.
     * @param securePassword   The secure password used for encryption.
     * @param walletEncryptType The encryption type to be used for the wallet.
     * @throws WalletException If an error occurs during wallet creation.
     */
	public void create(String walletFilePath, char[] securePassword, WalletEncryptType walletEncryptType) throws WalletException;
	
	 /**
     * Connects to an existing wallet file with the specified parameters.
     *
     * @param walletFilePath   The path to the existing wallet file.
     * @param securePassword   The secure password used to connect to the wallet.
     * @throws WalletException If an error occurs during wallet connection.
     */
	public void connect( String walletFilePath, char [] securePassword) throws WalletException;
	
	 /**
     * Changes the secure password of the connected wallet.
     *
     * @param currentSecurePassword The current secure password.
     * @param newSecurePassword     The new secure password.
     * @throws WalletException If an error occurs during password change.
     */
	public void changePassword(char[] currentSecurePassword, char[] newSecurePassword) throws WalletException;
	
	 /**
     * Disconnects from the connected wallet.
     *
     * @return True if disconnected successfully, false otherwise.
     */
	public boolean disConnect();
	
	 /**
     * Checks if the wallet is currently connected.
     *
     * @return True if connected, false otherwise.
     */
	public boolean isConnect();

	
	 /**
     * Adds a cryptographic key pair to the wallet.
     *
     * @param cryptoKeyInfo The information of the cryptographic key pair to add.
     * @throws WalletException If an error occurs during key addition.
     */
	public void addKey(CryptoKeyPairInfo cryptoKeyInfo) throws WalletException;
	
	 /**
     * Generates a random key with the specified ID and algorithm type.
     *
     * @param keyId             The ID of the key to generate.
     * @param keyAlgorithmType  The type of algorithm to use for key generation.
     * @throws WalletException If an error occurs during key generation.
     */
	public void generateRandomKey(String keyId, KeyAlgorithmType keyAlgorithmType) throws WalletException;
	
	  /**
     * Checks if a key with the specified key ID exists in the wallet.
     *
     * @param keyId The ID of the key.
     * @return True if the key exists, false otherwise.
     * @throws WalletException If an error occurs during key existence check.
     */
	public boolean isExistKey(String keyId) throws WalletException;
	
    /**
     * Retrieves the public key associated with the specified key ID.
     *
     * @param keyId The ID of the key.
     * @return The public key as a string.
     * @throws WalletException If an error occurs during key retrieval.
     */
	public String getPublicKey(String keyId) throws WalletException;
	
    /**
     * Retrieves the key algorithm associated with the specified key ID.
     *
     * @param keyId The ID of the key.
     * @return The key algorithm.
     * @throws WalletException If an error occurs during key algorithm retrieval.
     */
	public String getKeyAlgorithm(String keyId) throws WalletException;
	
	 /**
     * Retrieves the key element associated with the specified key ID.
     *
     * @param keyId The ID of the key.
     * @return The key element.
     * @throws WalletException If an error occurs during key retrieval.
     */
	public KeyElement getKeyElement(String keyId) throws WalletException;
	
	  /**
     * Retrieves a list of all key IDs present in the wallet.
     *
     * @return The list of key IDs.
     * @throws WalletException If an error occurs during key ID retrieval.
     */
	public List<String> getKeyIdList() throws WalletException;
	
	  /**
     * Removes the key associated with the specified key ID from the wallet.
     *
     * @param keyId The ID of the key to remove.
     * @throws WalletException If an error occurs during key removal.
     */
	public void removeKey(String keyId) throws WalletException;
	
	  /**
     * Removes all keys from the wallet.
     *
     * @throws WalletException If an error occurs during key removal.
     */
	public void removeAllKeys() throws WalletException;
	
	  /**
     * Retrieves the shared secret associated with the specified key ID and encoded compressed key.
     *
     * @param keyId              The ID of the key.
     * @param mEncodedCompressedKey The encoded compressed key.
     * @return The shared secret as a byte array.
     * @throws WalletException If an error occurs during shared secret retrieval.
     */
	public byte[] getSharedSecret(String keyId, String mEncodedCompressedKey) throws WalletException;
	
	 /**
     * Generates a compact signature from the hashed source using the specified key ID.
     *
     * @param keyId        The ID of the key to use for signing.
     * @param hashedSource The hashed source data.
     * @return The compact signature as a byte array.
     * @throws WalletException If an error occurs during signature generation.
     */
	public byte[] generateCompactSignatureFromHash(String keyId, byte[] hashedSource) throws WalletException;

}

