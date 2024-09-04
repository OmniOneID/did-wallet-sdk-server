/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.file;

import org.omnione.did.wallet.exception.WalletException;

public class WalletFileHandler {
    private static WalletFileHelper walletFileHelper;
    

    /**
     * Returns whether the SecretPhrase exists.
     *
     * @return SecretPhrase existence
     */
    public boolean isExistSecretPhrase() {
    	return walletFileHelper.isExistSecretPhrase();
    }
    
	/**
     * Create a SecretPhrase with password.
     *
     * @param securePassword password
     * @return Byte array of the generated SecretPhrase
     * @throws WalletException If an error occurs during SecretPhrase generation
     */
    public void generateSecretPhrase(char [] securePassword) throws WalletException {
    	walletFileHelper.generateSecretPhrase(securePassword);
    }
    
    /**
     * WalletFileHelper interface
     */
    public static interface WalletFileHelper {
    	 /**
         * Check that the wallet file exists.
         *
         * @return SecretPhrase existence
         */
    	boolean isExistSecretPhrase();
   	 
    	byte[] generateSecretPhrase(char [] securePassword) throws WalletException; 
    	 /**
         *  Use securePassword to authenticate the SecretPhrase.
         *
         * @param securePassword password
         * @return derivedKey Byte array of the generated SecretPhrase
         * @throws WalletException Fires when securePassword authentication fails
         */
    	byte[] authenticate(char [] securePassword) throws WalletException;  	
    
    	
    }
    
}
