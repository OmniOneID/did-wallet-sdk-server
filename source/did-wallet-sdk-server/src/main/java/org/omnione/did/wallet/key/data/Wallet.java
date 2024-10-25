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

import java.util.ArrayList;

import org.omnione.did.wallet.util.json.JsonConverterUtils;

public class Wallet {

	public static boolean ONETIME_LOAD = true;

	private HeadElement head;
	private ArrayList<KeyElement> keys;

	public void setHead(HeadElement headElement) {
		this.head = headElement;
	}

	public HeadElement getHead() {
		return head;
	}

	public ArrayList<KeyElement> getKeys() {

		if (keys == null) {
			return null;
		}

		ArrayList<KeyElement> lKeys = new ArrayList<KeyElement>();
		lKeys.addAll(keys);

		return lKeys;
	}

	public void setKeys(ArrayList<KeyElement> keys) {

		if (keys != null) {
			ArrayList<KeyElement> new_keys = new ArrayList<KeyElement>();
			new_keys.addAll(keys);
			this.keys = new_keys;
		} else {
			this.keys = null;
		}

	}

	public String toJson() {
		JsonConverterUtils gson = new JsonConverterUtils();
		return gson.toJson(this);
	}

	public void fromJson(String val) {
		JsonConverterUtils gson = new JsonConverterUtils();
		Wallet data = gson.fromJson(val, Wallet.class);
		head = data.getHead();
		keys = data.getKeys();

	}

}
