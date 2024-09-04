/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.exception;

public class WalletCommonException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6712733907628438694L;

	/**
	 * Error Code - Must be used within the int range.
	 */
	protected String errorCode;

	/**
	 * Error code message
	 */
	protected String errorMsg;

	/**
	 * Error reason
	 */
	protected String errorReason;

	public WalletCommonException(WalletErrorEnumInterface iwErrorEnum) {
		super("ErrorCode: " + iwErrorEnum.getCode() + ", Message: " + iwErrorEnum.getMsg());
		this.errorCode = iwErrorEnum.getCode();
		this.errorMsg = iwErrorEnum.getMsg();
	}

	public WalletCommonException(WalletErrorEnumInterface iwErrorEnum, Throwable throwable) {
		super("ErrorCode: " + iwErrorEnum.getCode() + ", Message: " + iwErrorEnum.getMsg(), throwable);
		this.errorCode = iwErrorEnum.getCode();
		this.errorMsg = iwErrorEnum.getMsg();
	}

	public WalletCommonException(WalletErrorEnumInterface iwErrorEnum, String errorReason) {
		super("ErrorCode: " + iwErrorEnum.getCode() + ", Message: " + iwErrorEnum.getMsg() + ", Reason: " + errorReason);
		this.errorCode = iwErrorEnum.getCode();
		this.errorMsg = iwErrorEnum.getMsg();
		this.errorReason = errorReason;

	}

	public WalletCommonException(WalletErrorEnumInterface iwErrorEnum, String errorReason, Throwable throwable) {
		super("ErrorCode: " + iwErrorEnum.getCode() + ", Message: " + iwErrorEnum.getMsg() + ", Reason: " + errorReason, throwable);
		this.errorCode = iwErrorEnum.getCode();
		this.errorMsg = iwErrorEnum.getMsg();
		this.errorReason = errorReason;
	}

	public WalletCommonException(String errorCode, String errorMsg) {
		super("ErrorCode: " + errorCode + ", Message: " + errorMsg);
		this.errorCode = errorCode;
		this.errorMsg = errorMsg;
	}

	public WalletCommonException(String errorCode, String errorMsg, Throwable throwable) {
		super("ErrorCode: " + errorCode + ", Message: " + errorMsg, throwable);
		this.errorCode = errorCode;
		this.errorMsg = errorMsg;
	}

	public WalletCommonException(String errorCode, String errorMsg, String errorReason) {
		super("ErrorCode: " + errorCode + ", Message: " + errorMsg + ", Reason: " + errorReason);
		this.errorCode = errorCode;
		this.errorMsg = errorMsg;
		this.errorReason = errorReason;
	}

	public WalletCommonException(String errorCode, String errorMsg, String errorReason, Throwable throwable) {
		super("ErrorCode: " + errorCode + ", Message: " + errorMsg + ", Reason: " + errorReason, throwable);
		this.errorCode = errorCode;
		this.errorMsg = errorMsg;
		this.errorReason = errorReason;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public String getErrorReason() {
		return errorReason;
	}

	public String getErrorMsg() {
		return errorMsg;
	}

}
