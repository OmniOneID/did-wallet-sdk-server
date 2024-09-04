/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.file;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.key.data.Wallet;

public class WalletFile {

	public static boolean ONETIME_LOAD = false;
	private String walletFilePath;

//	private static CryptoWallet data;
	private Wallet walletData;
	private final static String WALLET_FILE_EXTENSION_NAME = ".wallet";

	/**
	 * WalletFile constructor. Initialize by adding the wallet file extension to the specified path.
	 * @param pathWithName wallet file paths and names
	 */
	public WalletFile(String pathWithName) {

		String ext = null;
		int i = pathWithName.lastIndexOf('.');

		if (i > 0 && i < pathWithName.length() - 1) {
			ext = pathWithName.substring(i).toLowerCase();
		}

		if (ext == null || !ext.contentEquals(WALLET_FILE_EXTENSION_NAME)) {
			pathWithName = pathWithName + WALLET_FILE_EXTENSION_NAME;
		}

		walletFilePath = pathWithName;

	}

	/**
	 * Check that the wallet file exists.
	 *
	 * @return File Existence
	 */
	public boolean isExist() {
		File f = new File(walletFilePath);
		return f.exists();
	}

	/**
	 * Delete the wallet file.
	 */
	public void delete() {
		File f = new File(walletFilePath);
		if (f.exists()) {
			f.delete();
		}
	}
	
	 /**
	  * Clears the wallet data stored in memory.
     */
    public void clearData() {
    	walletData = null;
    }

	/**
	 *  Save the wallet data to a file and reload it.
	 *
	 * @param walletData Wallet data to store
	 * @throws WalletException Fired when a file write fails.
	 */
	public void write(Wallet walletData) throws WalletException {
		String data_str = walletData.toJson();

		try {
			writeToFile(data_str);
		} catch (IOException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_FILE_WRITE_FAIL, e);
		}
		try {
			loadFromFile();
		} catch (IOException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_FILE_LOAD_FAIL, e);
		}
	}

	/**
	 * Returns the currently stored wallet data.
	 *
	 * @return Saved CryptoWallet data
	 * @throws WalletException Fired when a file fails to load.
	 */
	public Wallet getData() throws WalletException {
		try {
			if (ONETIME_LOAD && walletData == null) {
				loadFromFile();
			} else if (!ONETIME_LOAD) {
				loadFromFile();
			}
		} catch (IOException e) {
			throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_FILE_LOAD_FAIL, e);
		}

		return walletData;
	}

	/**
	 * Returns the path to the wallet file.
	 *
	 * @return wallet file path
	 */
	public String getFilePath() {
		return walletFilePath;
	}

	/**
	 * (private method) Save wallet data as a wallet file.
	 * 
	 * @param data Data string to store
	 * @throws IOException Fired when a file write fails.
	 */
	private void writeToFile(String data) throws IOException {
		FileWriter fw = null;

		try {
			File file = new File(walletFilePath);
			fw = new FileWriter(file);
			fw.write(data);

		} finally {
			fw.close();
		}
	}

	/**
	 * (private method) Load the wallet file and save it as wallet data.
	 * 
	 * @throws IOException Fired when a file read fails.
	 */
	private void loadFromFile() throws IOException {
		FileReader fr = null;
		BufferedReader br = null;
		try {
			File file = new File(walletFilePath);
			fr = new FileReader(file);
			br = new BufferedReader(fr);
			StringBuilder buf = new StringBuilder();
			String line;
			while ((line = br.readLine()) != null) {
				buf.append(line);
			}
			walletData = new Wallet();
			walletData.fromJson(buf.toString());
		} finally {

			if (br != null)
				br.close();
			if (fr != null)
				fr.close();

		}
	}

}
