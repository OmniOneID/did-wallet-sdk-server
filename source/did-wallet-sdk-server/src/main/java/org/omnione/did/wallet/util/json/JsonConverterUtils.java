/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.util.json;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

public class JsonConverterUtils {
	public static JsonConverterUtils getGson() {
		return new JsonConverterUtils();
	}

	public static JsonConverterUtils getGsonPrettyPrinting() {
		return new JsonConverterUtils(true);
	}

	private Gson gson;

	public JsonConverterUtils() {
		super();
		gson = new GsonBuilder().disableHtmlEscaping().create();
	}

	public JsonConverterUtils(boolean prettyPrinting) {
		super();
		GsonBuilder builder = new GsonBuilder().disableHtmlEscaping();
		if (prettyPrinting) {
			builder.setPrettyPrinting();
		}
		gson = builder.create();
	}

	public <T> T fromJson(String json, Class<T> classOfT) throws JsonSyntaxException {
		return gson.fromJson(json, classOfT);
	}

	public String toJson(Object src) {
		return gson.toJson(src);
	}

}
