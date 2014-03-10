/*
 * Copyright 2004,2005 The Apache Software Foundation.
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
package org.apache.rampart;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This class holds nonce information per service.
 */
public class ServiceNonceCache {

    private Map<String, UniqueMessageAttributeCache> mapServiceNonceCache = Collections.synchronizedMap(new HashMap<String, UniqueMessageAttributeCache>());

    /**
     * This method will add a nonce value for a given service.
     * @param service The service url.
     * @param userName Given user name.
     * @param nonceValue Passed nonce value.
     * @param nonceLifeTime Maximum life span of a nonce value.
     */
    public void addNonceForService(String service, String userName, String nonceValue, int nonceLifeTime) {

        UniqueMessageAttributeCache nonceCache;
        if (this.mapServiceNonceCache.containsKey(service)) {
            nonceCache = this.mapServiceNonceCache.get(service);
        } else {
            nonceCache = new NonceCache(nonceLifeTime);
            this.mapServiceNonceCache.put(service, nonceCache);
        }
                
        nonceCache.addToCache(nonceValue, userName);
    }

    /**
     * This method will check whether the nonce value is repeating for the given service.
     * @param service The service url.
     * @param userName User name.
     * @param nonceValue Nonce value.
     * @return true if nonce value is repeating else false.
     */
    public boolean isNonceRepeatingForService(String service, String userName, String nonceValue){

        if (this.mapServiceNonceCache.containsKey(service)) {

            UniqueMessageAttributeCache nonceCache = this.mapServiceNonceCache.get(service);
            return nonceCache.valueExistsInCache(nonceValue, userName);           

        }

        return false;

    }

}
