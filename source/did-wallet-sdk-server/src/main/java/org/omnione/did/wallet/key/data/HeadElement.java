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
