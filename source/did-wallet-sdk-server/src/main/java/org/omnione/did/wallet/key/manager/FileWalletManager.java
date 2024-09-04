/* 
 * Copyright 2024 Raonsecure
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
