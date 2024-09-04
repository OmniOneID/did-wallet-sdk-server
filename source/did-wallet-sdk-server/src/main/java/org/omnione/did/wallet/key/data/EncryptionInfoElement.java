/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.key.data;

import org.omnione.did.wallet.util.json.JsonConverterUtils;

public class EncryptionInfoElement {
	private String aesAlgorithm;
	private String padding;
	private String mode;
	private int keySize;

	
	
	

	public String getAesAlgorithm() {
		return aesAlgorithm;
	}

	public void setAesAlgorithm(String aesAlgorithm) {
		this.aesAlgorithm = aesAlgorithm;
	}

	public String getPadding() {
		return padding;
	}

	public void setPadding(String padding) {
		this.padding = padding;
	}

	public String getMode() {
		return mode;
	}

	public void setMode(String mode) {
		this.mode = mode;
	}

	public int getKeySize() {
		return keySize;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}

	public String getSymmetricCipherTypeString() {
		StringBuilder sb = new StringBuilder();
		sb.append(this.aesAlgorithm);
		sb.append("-");
		sb.append(this.keySize*8);
		sb.append("-");
		sb.append(this.mode);

		return sb.toString();

	}

	public String toJson() {
		JsonConverterUtils gson = new JsonConverterUtils();
		return gson.toJson(this);
	}

}
