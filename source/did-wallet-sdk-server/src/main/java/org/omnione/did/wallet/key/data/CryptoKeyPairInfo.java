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

import java.security.PrivateKey;
import java.security.PublicKey;

import org.omnione.did.crypto.keypair.EcKeyPair;
import org.omnione.did.crypto.keypair.KeyPairInterface;


public class CryptoKeyPairInfo {
	private String keyId;
	private String algorithm;

	private KeyPairInterface keyPair;
	
	public enum KeyAlgorithmType {

		SECP256k1("Secp256k1"),  SECP256r1("Secp256r1"),RSA2048("Rsa2048");
		
		private String rawValue;
	
		private KeyAlgorithmType(String rawValue) {
			this.rawValue = rawValue;
		}
	
		public String getRawValue() {
			return rawValue;
		}
		public static KeyAlgorithmType fromValue(String rawValue) {
			for (KeyAlgorithmType type : values()) {
				if (type.getRawValue().equals(rawValue)) {
					return type;
				}
			}
			return null;
		}
	
		@Override
		public String toString() {
			switch (this) {
			case SECP256k1:
				return "Secp256k1";
			case RSA2048:
				return "Rsa2048";
			case SECP256r1:
				return "Secp256r1";
			default:
				return "Unknown";
			}
		}
		
	
	}

	
	public CryptoKeyPairInfo(String keyId, String algorithm, PublicKey publicKey, PrivateKey privateKey) {	
		this.keyId = keyId;
		this.algorithm = algorithm;
		keyPair = (KeyPairInterface) new EcKeyPair(publicKey, privateKey);
	}
		
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

	public PublicKey getPublicKey() {
		return (PublicKey) keyPair.getPublicKey();
	}
	
	public void setPublicKey(PublicKey publicKey) {
		keyPair.setPublicKey(publicKey);
	}
	
	public PrivateKey getPrivateKey() {
		return (PrivateKey) keyPair.getPrivateKey();
	}
	
	public void setPrivateKey(PrivateKey privateKey) {
		keyPair.setPrivateKey(privateKey);
	}
    
}
