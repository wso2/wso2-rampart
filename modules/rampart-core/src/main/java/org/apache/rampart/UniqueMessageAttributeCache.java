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

/**
 * An interface to cache nonce/sequence number values coming with messages.
 * This mainly helps to prevent replay attacks. There are few different ways to handle replay attacks.
 * 1. Cache nonce values.
 * 2. Use a sequence number.
 * 
 * "Web Services Security UsernameToken Profile 1.1 OASIS Standard Specification, 1 February 2006" specification only recommends
 * to cache nonce for a period. But there can be other mechanisms like using sequence number.
 * Therefore cache is implemented as an interface and later if we need to support sequence number scenario we can easily extend this. 
 * User: aj
 * Date: Apr 30, 2010
 * Time: 12:15:52 PM
 * To change this template use File | Settings | File Templates.
 */
public interface UniqueMessageAttributeCache {

    /**
     * Sets the maximum life time of a message id.
     * @param maxTime Maximum life time in seconds.
     */
    public void setMaximumLifeTimeOfAnAttribute(int maxTime);

     /**
     * Gets the maximum life time of a message id.
     * @return Gets message id life time in seconds.
     */
    public int getMaximumLifeTimeOfAnAttribute();

    /**
     * Add value to a cache. Value can be sequence or nonce value.
     * @param id - Nonce value or sequence number.
     * @param userName - User name parameter value of the UserNameToken.
     */
    public void addToCache(String id, String userName);

    /**
     * Checks whether value already exists in the cache for a given user name. 
     * @param id - Nonce or sequence id value of the newly received message.
     * @param userName - User name parameter value of the UserName token.
     * @return Returns true if nonce or sequence id is already received for given user name. Else false.
     */
    public boolean valueExistsInCache(String id, String userName);

    /**
     * Clears all recorded nonce values/sequence numbers.
     */
    public void clearCache();
}
