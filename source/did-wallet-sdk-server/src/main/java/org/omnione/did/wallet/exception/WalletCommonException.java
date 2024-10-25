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
