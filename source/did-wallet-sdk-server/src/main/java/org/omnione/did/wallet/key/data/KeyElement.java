/* 
 * Copyright 2024 Raonsecure
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
