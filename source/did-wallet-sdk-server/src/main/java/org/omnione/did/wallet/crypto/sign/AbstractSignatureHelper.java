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

package org.omnione.did.wallet.crypto.sign;

import java.security.PrivateKey;

import org.omnione.did.crypto.enums.DidKeyType;
import org.omnione.did.wallet.exception.WalletErrorCode;
import org.omnione.did.wallet.exception.WalletException;
import org.omnione.did.wallet.key.data.CryptoKeyPairInfo.KeyAlgorithmType;

public abstract class AbstractSignatureHelper {

	abstract public byte[] sign(byte[] originalHashedMessage, PrivateKey privateKey) throws WalletException;

	abstract public void verify(String algorithm, byte[] sign, byte[] publicKey, byte[] signedMessage) throws WalletException;
	
	public DidKeyType convertDidKeyType(String keyAlgorithm) throws WalletException {
		
		if(keyAlgorithm == null || keyAlgorithm.isEmpty()) {
			 throw new WalletException(WalletErrorCode.ERR_CODE_WALLET_INVALID_ALGORITHM_TYPE);
		}
		
	    if (keyAlgorithm.equals(KeyAlgorithmType.SECP256k1.getRawValue())) {
            return DidKeyType.SECP256K1_VERIFICATION_KEY_2018;
        } else if (keyAlgorithm.equals(KeyAlgorithmType.SECP256r1.getRawValue())) {
            return DidKeyType.SECP256R1_VERIFICATION_KEY_2018;
        } else if (keyAlgorithm.equals(KeyAlgorithmType.RSA2048.getRawValue())) {
            return DidKeyType.RSA_VERIFICATION_KEY_2018;
        } else {
            throw new IllegalArgumentException("Invalid key algorithm: " + keyAlgorithm);
        }
	}

}
