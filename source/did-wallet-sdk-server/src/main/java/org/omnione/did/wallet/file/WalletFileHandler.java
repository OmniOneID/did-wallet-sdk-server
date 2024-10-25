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
