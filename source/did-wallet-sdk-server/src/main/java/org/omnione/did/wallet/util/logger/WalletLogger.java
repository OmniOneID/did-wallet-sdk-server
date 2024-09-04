/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.util.logger;

import java.util.logging.Level;

import org.omnione.did.wallet.util.json.JsonConverterUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;

//purpose : print visible hex log

import com.google.gson.JsonParser;

public class WalletLogger {

	private static final String SLF4J_NOP = "NOP";

	// java util logging
	private static java.util.logging.Logger jul = java.util.logging.Logger.getLogger("WalletLogger");
	// slf4j
	private static Logger logger = null;

	private static LoggerType LOGGER_TYPE = LoggerType.SLF4J;

	static {
		try {
			Class.forName("org.slf4j.LoggerFactory");

			logger = LoggerFactory.getLogger(WalletLogger.class);

			if (logger != null && !SLF4J_NOP.equalsIgnoreCase(logger.getName())) {
				LOGGER_TYPE = LoggerType.SLF4J;
			} else {
				LOGGER_TYPE = LoggerType.JUL;
			}
		} catch (Exception e) {
			LOGGER_TYPE = LoggerType.JUL;
		}
	}

	public static boolean FLAG = false;
	public static boolean SYSOUT_PRINT = false;

	private static LogLevelType GDP_LOG_LEVEL = LogLevelType.INFO;

	public static void setLevel(String gdpLogLevel) {
		try {
			GDP_LOG_LEVEL = LogLevelType.valueOf(gdpLogLevel.toUpperCase());
		} catch (Exception e) {
			GDP_LOG_LEVEL = LogLevelType.INFO;
		}
	}
	public static void setLevel(LogLevelType gdpLogLevel) {
		try {
			GDP_LOG_LEVEL = gdpLogLevel;
		} catch (Exception e) {
			GDP_LOG_LEVEL = LogLevelType.INFO;
		}
	}

	private static void log(Level level, String message, Object... arguments) {
		dolog(level, message, false, arguments);
	}
	
	private static void dolog(Level level, String message, boolean bFatal, Object... arguments) {
		if(bFatal || (FLAG && level.intValue() >= GDP_LOG_LEVEL.getLevel().intValue())) {
			if(SYSOUT_PRINT) {
				System.out.println(message);
			} else {
				switch (LOGGER_TYPE) {
					case SLF4J:
						slf4jLog(level, message, arguments);
						break;
					case JUL:
						jul.log(Level.INFO, message);
						break;
				}
			}
		}
	}

	private static void slf4jLog(Level level, String message, Object... arguments) {
		if(Level.SEVERE.equals(level)) {
			logger.error(message, arguments);
		} else if(Level.WARNING.equals(level)) {
			logger.warn(message, arguments);
		} else if(Level.INFO.equals(level)) {
			logger.info(message, arguments);
		} else if(Level.FINE.equals(level)) {
			logger.debug(message, arguments);
		} else if(Level.FINEST.equals(level)) {
			logger.trace(message, arguments);
		}
	}

	public static void print(String message) {
		log(Level.FINE, message);
	}

	public static void fatal(String message) {
		dolog(Level.SEVERE, message, true);
	}

	public static void error(String message) {
		error("error", message);
	}
	public static void error(String title, String message) {
		print(Level.SEVERE, title, message);
	}
	public static void error(String title, String message, Object... argument) {
		print(Level.SEVERE, title, message, argument);
	}

	public static void warn(String message) {
		warn("warn", message);
	}
	public static void warn(String title, String message) {
		print(Level.WARNING, title, message);
	}
	public static void warn(String title, String message, Object... argument) {
		print(Level.WARNING, title, message, argument);
	}

	public static void info(String message) {
		info("info", message);
	}
	public static void info(String title, String message) {
		print(Level.INFO, title, message);
	}
	public static void info(String title, String message, Object... argument) {
		print(Level.INFO, title, message, argument);
	}

	public static void debug(String message) {
		debug("debug", message);
	}
	public static void debug(String title, String message) {
		print(Level.FINE, title, message);
	}
	public static void debug(String title, String message, Object... argument) {
		print(Level.FINE, title, message, argument);
	}

	public static void trace(String message) {
		trace("trace", message);
	}
	public static void trace(String title, String message) {
		print(Level.FINEST, title, message);
	}
	public static void trace(String title, String message, Object... argument) {
		print(Level.FINEST, title, message, argument);
	}

	public static void print(String title, String message) {
		print(Level.FINE, title, message);
	}
	public static void print(String title, String message, Object... argument) {
		print(Level.FINE, title, message, argument);
	}

	public static void print(Level level, String title, String message, Object... argument) {
		if (FLAG == true) {
			log(level, "[" + title + "] " + message, argument);
		}
	}

	public static void printHex(String title, byte[] input) {

		if (FLAG == true & title != null & input != null) {
			log(Level.FINE,"[" + title + "] " + input.length + "byte");
			printHex(input);

		} // flag
	}// printHex

	public static void printPrettyJson(String title, String message) {
		if (FLAG == true) {
			log(Level.FINE,"[" + title + "]\n" + WalletLogger.toPrettyFormat(message));
		}
	}

	public static String toPrettyFormat(String jsonString) {
		JsonParser parser = new JsonParser();
		JsonObject json = parser.parse(jsonString).getAsJsonObject();

		JsonConverterUtils gson = new JsonConverterUtils(true);
		String prettyJson = gson.toJson(json);

		return prettyJson;
	}

	private static void printHex(byte[] input) {

		if (FLAG == true) {

			int length = input.length;
			int line = length / 16;
			log(Level.FINE,"> 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15    0123456789abcdef");
			log(Level.FINE,"> ===============================================    ================");

			for (int i = 0; i <= line; i++) {
				StringBuffer d = new StringBuffer(83);
				int column = Math.min(16, (length - i * 16));
				for (int j = 0; j < column; j++) {
					char hi = forDigit(input[i * 16 + j] >> 4 & 0x0F, 16);
					char lo = forDigit(input[i * 16 + j] & 0x0F, 16);
					d.append(Character.toUpperCase(hi));
					d.append(Character.toUpperCase(lo));
					d.append(':');
				}
				for (int j = 16; j >= column; j--) {
					d.append("   ");
				}
				for (int j = 0; j < column; j++) {
					char tmp = (char) input[i * 16 + j];
					if (isISOControl(tmp)) {
						d.append('.');
					}
					else {
						d.append((char) input[i * 16 + j]);
					}
				}
				log(Level.FINE,"> " + d);
			}

		} // flag

	}// printHex

	private static char forDigit(int i, int j) {
		if (i >= j || i < 0) {
			return '\0';
		}
		if (j < 2 || j > 36) {
			return '\0';
		}
		if (i < 10) {
			return (char) (48 + i);
		}
		else {
			return (char) (87 + i);
		}
	}

	private static boolean isISOControl(char c) {
		return c <= '\237' && (c <= '\037' || c >= '\177');
	}


	public enum LoggerType {
		JUL,
		SLF4J
	}

	/**
	 * ERROR -> Level.SEVERE
	 * WARN  -> Level.WARNING
	 * INFO  -> Level.INFO
	 * DEBUG -> Level.FINE
	 * TRACE -> Level.FINEST
	 */
	public enum LogLevelType {
		ERROR("ERROR", Level.SEVERE),
		WARN("WARN", Level.WARNING),
		INFO("INFO", Level.INFO),
		DEBUG("DEBUG", Level.FINE),
		TRACE("TRACE", Level.FINEST);

		private Level level;

		LogLevelType(String levelType, Level level) {
			this.level = level;
		}

		public Level getLevel() {
			return level;
		}
	}
}
