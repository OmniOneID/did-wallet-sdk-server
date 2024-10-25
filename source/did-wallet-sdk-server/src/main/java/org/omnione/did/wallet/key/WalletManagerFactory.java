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
