/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.key.data;

import org.omnione.did.wallet.util.json.JsonConverterUtils;

public class HeadElement {
	private EncryptionInfoElement encryptionInfo;
	private SecureKeyInfoElement secureKeyInfo;
	private int version;
	private EncodingElement encoding;
	
	
	

	public EncryptionInfoElement getEncryptionInfo() {
		return encryptionInfo;
	}




	public void setEncryptionInfo(EncryptionInfoElement encryptionInfo) {
		this.encryptionInfo = encryptionInfo;
	}




	public SecureKeyInfoElement getSecureKeyInfo() {
		return secureKeyInfo;
	}




	public void setSecureKeyInfo(SecureKeyInfoElement secureKeyInfo) {
		this.secureKeyInfo = secureKeyInfo;
	}




	public int getVersion() {
		return version;
	}




	public void setVersion(int version) {
		this.version = version;
	}




	public EncodingElement getEncoding() {
		return encoding;
	}




	public void setEncoding(EncodingElement encoding) {
		this.encoding = encoding;
	}




	public String toJson() {
		JsonConverterUtils gson = new JsonConverterUtils();
		return gson.toJson(this);
	}
}
