/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.exception;

public class WalletException extends WalletCommonException {

	private static final long serialVersionUID = 2584536544817080786L;

	public WalletException(String code) {
		super(WalletErrorCode.getEnumByCode(code));
	}
	
	public WalletException(String code, String msg) {
		super(code, msg);
	}
	
	
	public WalletException(String code, Throwable throwable)  {
		super(WalletErrorCode.getEnumByCode(code), throwable);
	}
	
	public WalletException(WalletErrorCode iwErrorCode)  {
		super(iwErrorCode);
	}
	
	public WalletException(WalletErrorCode iwErrorCode, Throwable throwable)  {
		super(iwErrorCode, throwable);
	}


	public String getStatusCode() {
		return errorCode;
	}

	@Override
	public String getErrorCode(){		
		return errorCode;
	}

	@Override
	public String getErrorReason() {
		return errorReason;
	}
}
