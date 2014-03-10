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
 * An abstract class which implements UniqueMessageAttributeCache interface.
 */
public abstract class AbstractUniqueMessageAttributeCache implements UniqueMessageAttributeCache {

    /**
     * Maximum lift time of a cached value. If cached value exceeds this value it will be discarded.
     */
    private int maximumLifeTimeOfNonce = 60 * 5;

    /**
     * Default constructor.
     */
    public AbstractUniqueMessageAttributeCache()
    {
    }

    /**
     * Constructor with maximum life time as a parameter.
     * @param maxTime Maximum life time in seconds.
     */
    public AbstractUniqueMessageAttributeCache(int maxTime)
    {
        maximumLifeTimeOfNonce = maxTime;
    }

    /**
     * Sets the maximum life time of a message id.
     * @param maxTime Maximum life time in seconds.
     */
    public void setMaximumLifeTimeOfAnAttribute(int maxTime)
    {
        maximumLifeTimeOfNonce = maxTime;
    }

    /**
     * Gets the maximum life time of a message id.
     * @return Gets message id life time in seconds.
     */
    public int getMaximumLifeTimeOfAnAttribute()
    {
        return maximumLifeTimeOfNonce;
    }
}
