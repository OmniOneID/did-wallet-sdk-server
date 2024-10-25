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

package org.omnione.did.wallet.exception;

public enum WalletErrorCode implements WalletErrorEnumInterface {

	// base
	ERR_CODE_WALLET_SDK_BASE("SSDKWLT", ""),

	// crypto, sign
	ERR_CODE_COMMON_BASE(ERR_CODE_WALLET_SDK_BASE, "01", ""),

	ERR_CODE_CRYPTO_ENCRYPT(ERR_CODE_COMMON_BASE, 	"001",  "Failed to encrypt"),
	ERR_CODE_CRYPTO_DECRYPT(ERR_CODE_COMMON_BASE, 	"002", 	"Failed to decrypt"),
	ERR_CODE_CRYPTO_GEN_RANDOM_FAIL(ERR_CODE_COMMON_BASE, "003", "Failed to generate random byte"),
	ERR_CODE_CRYPTO_GEN_KEY_FAIL(ERR_CODE_COMMON_BASE, "004",	"Failed to generate key"),
	ERR_CODE_CRYPTO_COMPRESS_PUBLIC_KEY_FAIL(ERR_CODE_COMMON_BASE,     "005",   "Failed to compress PublicKey"),
	ERR_CODE_CRYPTO_UNCOMPRESS_PUBLIC_KEY_FAIL(ERR_CODE_COMMON_BASE,     "006",   "Failed to uncompress PublicKey"),
	ERR_CODE_SIG_FAIL_SIGN(ERR_CODE_COMMON_BASE, "007", 	"Failed to signature"),
	ERR_CODE_SIG_VERIFY_SIGN_FAIL(ERR_CODE_COMMON_BASE, "008", "Verify signature is failed"),
	ERR_CODE_SIG_COMPRESS_SIGN_FAIL(ERR_CODE_COMMON_BASE, "009", "Failed to compress signature"),

	// wallet
	ERR_CODE_WALLET_BASE(ERR_CODE_WALLET_SDK_BASE, "02", ""),

	ERR_CODE_WALLET_DISCONNECT(ERR_CODE_WALLET_BASE, 						"001", "WalletManager is disconnected"),
	ERR_CODE_WALLET_FILE_LOAD_FAIL(ERR_CODE_WALLET_BASE, 					"002", "Failed to load the WalletFile"),
	ERR_CODE_WALLET_FILE_WRITE_FAIL(ERR_CODE_WALLET_BASE, 		"003", "Failed to write the WalletFile"),

	ERR_CODE_WALLET_KEYID_NOT_EXIST(ERR_CODE_WALLET_BASE, "004", "The keyId does not exist"),
	ERR_CODE_WALLET_KEYID_ALREADY_EXIST(ERR_CODE_WALLET_BASE, "005", "The KeyId is already existed"),
	ERR_CODE_WALLET_KEYID_EMPTY_NAME(ERR_CODE_WALLET_BASE, "006", "The Name for KeyId is empty"),
	ERR_CODE_WALLET_INVALID_ALGORITHM_TYPE(ERR_CODE_WALLET_BASE, "007",	"Algorithm type is invalid"),
	ERR_CODE_WALLET_INVALID_KEYID_NAME(ERR_CODE_WALLET_BASE, "008",	"The Name for KeyId must only be alphaNumeric"),
	ERR_CODE_WALLET_IWKEY_IS_NULL(ERR_CODE_WALLET_BASE, "009",	"IWKey is null"),
	ERR_CODE_WALLET_INVALID_PRIVATE_KEY(ERR_CODE_WALLET_BASE, "010",	"Invalid PrivateKey"),
	ERR_CODE_WALLET_INVALID_PUBLIC_KEY(ERR_CODE_WALLET_BASE, "011",	"Invalid PublicKey"),
	ERR_CODE_WALLET_KEYINFO_EMPTY(ERR_CODE_WALLET_BASE, "012",  "KeyInfo is empty"),

	
	ERR_CODE_WALLET_PASSWORD_NOT_SET(ERR_CODE_WALLET_BASE, "013",	"The password does not set"),
	ERR_CODE_WALLET_PASSWORD_NOT_MATCH_WITH_THE_SET_ONE(ERR_CODE_WALLET_BASE, "014",	"The password does not match with the set one"),
	ERR_CODE_WALLET_INVALID_PASSWORD(ERR_CODE_WALLET_BASE, "015",	"The password is(are) invalid for use"),
	ERR_CODE_WALLET_PASSWORD_SAME_AS_OLD(ERR_CODE_WALLET_BASE, "016",	"New password is the same as the old one"),
	
	
	ERR_CODE_WALLET_AES_ENCRYPT_FAIL(ERR_CODE_WALLET_BASE, "017", "AES Encryption is failed"),
	ERR_CODE_WALLET_AES_DECRYPT_FAIL(ERR_CODE_WALLET_BASE, "018", "AES Decryption is failed"),
	ERR_CODE_WALLET_GEN_SECRET_FAIL(ERR_CODE_WALLET_BASE, 			"019",	"Failed to generate shared secret"),



	ERR_CODE_WALLET_INVALID_SIGN_VALUE(ERR_CODE_WALLET_BASE, "020", "Sign value is invalid"),
	ERR_CODE_WALLET_NOT_FIND_RECID(ERR_CODE_WALLET_BASE, "021", "could not find recid."),
	ERR_CODE_WALLET_FAIL_CONVERT_COMPACT(ERR_CODE_WALLET_BASE, "022", "fail convert sign data to eostype."),
	ERR_CODE_WALLET_INVALID_R_S_VALUE(ERR_CODE_WALLET_BASE, "023", "The r value must be 32 bytes."),
	

	ERR_CODE_WALLET_DEFAULTKEYSTORE_KEYGEN_FAIL(ERR_CODE_WALLET_BASE, "024",	"Key generation in DefaultKeyStore is fail"),
	ERR_CODE_WALLET_DEFAULTKEYSTORE_AUTHENTICATE_FAIL(ERR_CODE_WALLET_BASE, "025",		"Password authentication failed"),

	ERR_CODE_WALLET_INVALID_METHODNAME(ERR_CODE_WALLET_BASE, "026", "Method name must be lower case alphanumeric (colon accepted) and have range between from 1 to 20 length"),
	
	ERR_CODE_WALLET_ADD_KEY_FAIL(ERR_CODE_WALLET_BASE, "027",	"Failed to add the key"),

	ERR_CODE_WALLET_ALREADY_SECRET_PHRASE(ERR_CODE_WALLET_BASE, 			"028",	"SecretPhrase already exists"),
	ERR_CODE_WALLET_INVALID_SECRET_PHRASE(ERR_CODE_WALLET_BASE, 			"029",	"Invalid SecretPhrase"),

	ERR_CODE_WALLET_ALREADY_FILE(ERR_CODE_WALLET_BASE, 			"030",	"The file already exists"),
	ERR_CODE_WALLET_NOT_EXISTS_FILE(ERR_CODE_WALLET_BASE, 			"031",	"The file not exists"),

	ERR_CODE_WALLET_INVALID_WALLET_FILE(ERR_CODE_WALLET_BASE, "032",  "Invalid wallet file path with name"),

	;
	
	
	private String code;
	private String msg;

	private WalletErrorCode(String code, String msg) {
		this.msg = msg;
		this.code = code;
	}

	private WalletErrorCode(WalletErrorCode parentCode, String addCode, String msg) {
		this.msg = msg;
		this.code = parentCode.getCode() + addCode;
	}

	@Override
	public String getMsg() {
		return msg;
	}

	@Override
	public String getCode() {
		return code;
	}
	
	public static WalletErrorEnumInterface getEnumByCode(String code) {
		
		WalletErrorCode agentTypes[] = WalletErrorCode.values();
		for (WalletErrorCode iwCode : agentTypes) {
			if(iwCode.getCode() == code){
				return iwCode;
			}
		}
		
		throw new AssertionError("Unknown Enum Code");

	}

}