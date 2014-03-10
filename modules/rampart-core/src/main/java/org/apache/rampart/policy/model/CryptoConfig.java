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

package org.apache.rampart.policy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.Constants;
import org.apache.neethi.PolicyComponent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import java.util.Iterator;
import java.util.Properties;

/**
 * Policy model bean to capture crypto information.
 * 
 * Example:
<pre>
<ramp:crypto provider="org.apache.ws.security.components.crypto.Merlin">
    <ramp:property name="keystoreType">JKS</ramp:property>
    <ramp:property name="keystoreFile">/path/to/file.jks</ramp:property>
    <ramp:property name="keystorePassword">password</ramp:property>
</ramp:crypto>
</pre>
 */
public class CryptoConfig implements Assertion {
    
    public final static String CRYPTO_LN = "crypto";
    public final static String PROVIDER_ATTR = "provider";
    public final static String PROPERTY_LN = "property";
    public final static String PROPERTY_NAME_ATTR = "name";
    public final static String CRYPTO_KEY_ATTR = "cryptoKey";
    public final static String CACHE_REFRESH_INTVL = "cacheRefreshInterval";
    public static final String CACHE_ENABLED = "enableCryptoCaching";

    private Properties prop;

    private boolean cacheEnabled = true;

    private String provider;
    private String cryptoKey;
    private String cacheRefreshInterval;

    public String getCryptoKey() {
        return cryptoKey;
    }

    public void setCryptoKey(String cryptoKey) {
        this.cryptoKey = cryptoKey;
    }

    public String getCacheRefreshInterval() {
        return cacheRefreshInterval;
    }

    public void setCacheRefreshInterval(String cacheRefreshInterval) {
        this.cacheRefreshInterval = cacheRefreshInterval;
    }

    public Properties getProp() {
        return prop;
    }

    public void setProp(Properties prop) {
        this.prop = prop;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }
    
    public QName getName() {
        return new QName(RampartConfig.NS, CRYPTO_LN);
    }

    public boolean isOptional() {
        // TODO TODO
        throw new UnsupportedOperationException("TODO");
    }
 
    public PolicyComponent normalize() {
        // TODO TODO
        throw new UnsupportedOperationException("TODO");
    }

    public boolean isCacheEnabled() {
        return cacheEnabled;
    }

    public void setCacheEnabled(boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String prefix = writer.getPrefix(RampartConfig.NS);
        
        if (prefix == null) {
            prefix = RampartConfig.NS;
            writer.setPrefix(prefix, RampartConfig.NS);
        }
        
        writer.writeStartElement(prefix, CRYPTO_LN, RampartConfig.NS);
        
        if (getProvider() != null) {
            writer.writeAttribute(PROVIDER_ATTR, getProvider());
        }

        if(getCryptoKey() != null){
            writer.writeAttribute(CRYPTO_KEY_ATTR, getCryptoKey());
        }

        if(getCacheRefreshInterval() != null){
            writer.writeAttribute(CACHE_REFRESH_INTVL, getCacheRefreshInterval());    
        }

        if(!isCacheEnabled()){
            writer.writeAttribute(CACHE_ENABLED, Boolean.toString(isCacheEnabled()));
        }
        
        String key;
        String value;
        
        for (Iterator iterator = prop.keySet().iterator(); iterator.hasNext();) {
            key = (String) iterator.next();
            value = prop.getProperty(key);
            writer.writeStartElement(RampartConfig.NS, PROPERTY_LN);

            writer.writeAttribute("name", key);

            writer.writeCharacters(value);
            writer.writeEndElement();
        }
        
        writer.writeEndElement();
    }
    
    public boolean equal(PolicyComponent policyComponent) {
        throw new UnsupportedOperationException();
    }

    public short getType() {
        return Constants.TYPE_ASSERTION;
    }
    
}
