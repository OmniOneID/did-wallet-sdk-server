/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.wallet.util.json;

import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;

public class JsonSortUtils {

	@SuppressWarnings("unchecked")
	private static TreeMap<String, Object> sortTreeMapChange(Map<String, Object> map) {

		TreeMap<String, Object> resultTreeMap = new TreeMap<String, Object>();

		for (String key : map.keySet()) {
			Object value = map.get(key);
			if (value instanceof LinkedTreeMap) {
				LinkedTreeMap<String, Object> linkedTreeMap = (LinkedTreeMap<String, Object>) value;
				TreeMap<String, Object> treeMap = new TreeMap<String, Object>(linkedTreeMap);
				treeMap = sortTreeMapChange(treeMap);
				resultTreeMap.put(key, treeMap);
			}else if (value instanceof ArrayList) {
				ArrayList listDataTemp = new ArrayList();
				ArrayList listData = (ArrayList) value;
				for (Object object : listData) {
					
					if (object instanceof String) {
						String newObject = (String) object;
						listDataTemp.add(newObject);
					} 
					else if (object instanceof Double) {
						Double newObject = (Double) object;
						listDataTemp.add(newObject);
					} 
					else {
						LinkedTreeMap<String, Object> newObject = (LinkedTreeMap<String, Object>) object;
						TreeMap<String, Object> treeMap = sortTreeMapChange(newObject);
						listDataTemp.add(treeMap);
					}
				}

		
				resultTreeMap.put(key, listDataTemp);
			}
			else if (value instanceof Double) {
				resultTreeMap.put(key, ((Double) value).intValue());
			}
			else {
				resultTreeMap.put(key, value);
			}
		}

		return resultTreeMap;
	}

	@SuppressWarnings("unchecked")
	public static String sortJsonString(Gson gson, String json) {
		TreeMap<String, Object> map = gson.fromJson(json, TreeMap.class);
		TreeMap<String, Object> converterMap = sortTreeMapChange(map);
		String sortedJson = gson.toJson(converterMap);
		return sortedJson;
	}

	@SuppressWarnings("unchecked")
	public static String sortJsonString(JsonConverterUtils gson, String json) {
		TreeMap<String, Object> map = gson.fromJson(json, TreeMap.class);
		TreeMap<String, Object> converterMap = sortTreeMapChange(map);
		String sortedJson = gson.toJson(converterMap);
		return sortedJson;
	}

}
