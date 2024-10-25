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

package org.omnione.did.wallet.key.manager;

import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.key.adapter.WalletManagerAdapter;

public class FileWalletManager extends WalletManagerAdapter {

	public FileWalletManager() {}
	
	public FileWalletManager(String walletfile_pathWithName) throws WalletException {
		super(walletfile_pathWithName);
	}

}
