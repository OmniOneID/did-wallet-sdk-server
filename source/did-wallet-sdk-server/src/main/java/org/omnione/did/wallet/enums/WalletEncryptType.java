/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.enums;

import java.util.EnumSet;

public enum WalletEncryptType {
	AES_256_CBC_PKCS5Padding("AES-256-CBC-PKCS5Padding");
	
	
	String aesAlgorithm; 
	Integer keySize; 
	String mode; 
	String padding; 

	private String rawValue;

	WalletEncryptType(String rawValue) {
		this.rawValue = rawValue;	
	}
	

	public String getRawValue() {
		return rawValue;
	}
	
	public static WalletEncryptType fromString(String text) {
		for (WalletEncryptType b : WalletEncryptType.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<WalletEncryptType> all() {
		return EnumSet.allOf(WalletEncryptType.class);
	}

}
