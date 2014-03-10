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

import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

/**
 * This is a basic implementation of UniqueMessageAttributeCache. In this implementation we will cache incomming
 * nonce value for a period of time. The life time can be defined in the services.xml. If not defined
 * the default value will be 5 minutes.
 */
public class NonceCache extends AbstractUniqueMessageAttributeCache {

    class Nonce
    {
        String nonceValue;
        String userName;

        public Nonce(String nonce, String user)
        {
            this.nonceValue = nonce;
            this.userName = user;
        }

        @Override
        public boolean equals(Object another)
        {
        	if (another == null){
        		return false;
        	} 
        	
        	if (another == this) {
        		return true;
        	}
        	
        	if (!(another instanceof Nonce)){
        		return false;
        	} 
        	
        	
            Nonce otherNonce = (Nonce)another;
            if (this.userName.equals(otherNonce.userName) && this.nonceValue.equals(otherNonce.nonceValue))
            {
                return true;
            }
            return false;
        }

        @Override
        public int hashCode()
        {
            return (this.userName.hashCode() * 13 +  this.nonceValue.hashCode() * 7);
        }
    }

    private Map<Nonce, Calendar> mapIdNonce = new HashMap<Nonce, Calendar>();

    private final ReentrantLock lock = new ReentrantLock();

    public NonceCache()
    {
        super();
    }
    
    public NonceCache(int maxLifeTime)
    {
        super(maxLifeTime);
    }

    /**
     * @inheritdoc
     */    
    public void addToCache(String id, String userName) {

        Nonce nonce = new Nonce(id, userName);
        Calendar rightNow = Calendar.getInstance();

        lock.lock();
        try {
            mapIdNonce.put(nonce, rightNow);
        } finally {
            lock.unlock();
        }

    }

    /**
     * @inheritdoc
     */
    public boolean valueExistsInCache(String id, String userName) {

        lock.lock();

        try {
            clearStaleNonceIds();
        } finally {
            lock.unlock();
        }
        
        Nonce nonce = new Nonce(id, userName);
        return mapIdNonce.containsKey(nonce);
    }

    /**
     * @inheritdoc
     */
    public void clearCache() {

        lock.lock();
        try {
            mapIdNonce.clear();
        } finally {
            lock.unlock();
        }
    }

    /**
     * This method will clear stale nonce ids from the map.
     */
    private void clearStaleNonceIds()
    {
        Calendar rightNow = Calendar.getInstance();

        int maxLifeTime = getMaximumLifeTimeOfAnAttribute();

        rightNow.add(Calendar.SECOND, -(maxLifeTime));
        long timeBeforeMaxLifeTime = rightNow.getTimeInMillis();
        
        Iterator iterator = mapIdNonce.entrySet().iterator();

        while (iterator.hasNext()) {

            Map.Entry pair = (Map.Entry)iterator.next();
            Calendar itemDate = (Calendar)pair.getValue();

            long itemAddedTime = itemDate.getTimeInMillis();

            if (timeBeforeMaxLifeTime > itemAddedTime)
            {
                iterator.remove();
            }
        }


    }
}
