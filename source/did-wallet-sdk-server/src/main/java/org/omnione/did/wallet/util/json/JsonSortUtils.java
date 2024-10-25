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
