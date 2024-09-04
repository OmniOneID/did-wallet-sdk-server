/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.key.data;

import org.omnione.did.crypto.enums.MultiBaseType;


public class EncodingElement {

	private String keyEncodingType = MultiBaseType.base58btc.getCharacter();

	public String getKeyEncodingType() {
		return keyEncodingType;
	}

	public void setKeyEncodingType(String keyEncodingType) {
		this.keyEncodingType = keyEncodingType;
	}
	
	

}
