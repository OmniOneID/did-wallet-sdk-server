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

public class SecureKeyInfoElement {

	private String salt; 
	private int iterations;
	private String secretPhrase;

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public int getIterations() {
		return iterations;
	}

	public void setIterations(int iterations) {
		this.iterations = iterations;
	}

	public String getSecretPhrase() {
		return secretPhrase;
	}

	public void setSecretPhrase(String secretPhrase) {
		this.secretPhrase = secretPhrase;
	}

	public String toJson() {
		JsonConverterUtils gson = new JsonConverterUtils();
		return gson.toJson(this);
	}
}
