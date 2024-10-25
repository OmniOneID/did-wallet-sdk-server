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

public class KeyElement{
	private String keyId;
	private String algorithm;
	private String publicKey;
	private String privateKey;

	public String getKeyId() {
		return keyId;
	}

	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public String toJson() {
		JsonConverterUtils gson = new JsonConverterUtils();
		return gson.toJson(this);
	}

	public void fromJson(String val) {
		JsonConverterUtils gson = new JsonConverterUtils();
		KeyElement data = gson.fromJson(val, KeyElement.class);

		keyId = data.getKeyId();	
		algorithm = data.getAlgorithm();
		publicKey = data.getPublicKey();
		privateKey = data.getPrivateKey();
	}

}
