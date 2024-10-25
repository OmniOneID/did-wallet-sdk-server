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
