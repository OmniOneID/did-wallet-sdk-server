/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.key;

import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.file.WalletFile;
import org.omnione.did.wallet.key.manager.FileWalletManager;

public class WalletManagerFactory {

		public enum WalletManagerType {
			FILE, ;
		}

		public static void setKeyOneTimeLoad(boolean load) {
			WalletFile.ONETIME_LOAD = load;
		}
	
//		public static KeyManagerInterface getKeyManager(KeyManagerType type, String keyFile_pathWithName, char [] pwd ) throws WalletException {
//			
//			KeyManagerInterface manager = null;
//			
//			switch (type) {
//			case FILE:
//				manager = new FileKeyManager(keyFile_pathWithName, pwd);
//				break;
//			default:
//				break;
//			}
//			
//			return manager;
//		}
		
//		public static KeyManagerInterface getKeyManager(KeyManagerType type, String keyFile_pathWithName) throws WalletException {
//			
//			KeyManagerInterface manager = null;
//			
//			switch (type) {
//			case FILE:
//				manager = new FileKeyManager(keyFile_pathWithName);
//				break;
//			default:
//				break;
//			}
//			
//			return manager;
//		}
		
		public static WalletManagerInterface getWalletManager(WalletManagerType type, String keyFile_pathWithName) throws WalletException {
			WalletManagerInterface manager = null;
			switch (type) {
				case FILE:
					manager = new FileWalletManager(keyFile_pathWithName);
					break;
				default:
					break;
			}

			return manager;
		}
		
		public static WalletManagerInterface getWalletManager(WalletManagerType type) throws WalletException {
			WalletManagerInterface manager = null;
			
			switch (type) {
			case FILE:
				manager = new FileWalletManager();
				break;
			default:
				break;
			}

			return manager;
		}
	}
