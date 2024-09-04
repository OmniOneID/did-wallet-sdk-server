/* 
 * Copyright 2024 Raonsecure
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
