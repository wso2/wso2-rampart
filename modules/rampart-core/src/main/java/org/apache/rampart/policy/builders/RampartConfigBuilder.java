/*
 * Copyright 2001-2004 The Apache Software Foundation.
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
package org.apache.rampart.policy.builders;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.rampart.policy.model.*;

import javax.xml.namespace.QName;

public class RampartConfigBuilder implements AssertionBuilder {

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        RampartConfig rampartConfig = new RampartConfig();

        OMElement childElement;

        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.USER_LN));
        if (childElement != null) {
            rampartConfig.setUser(childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.USER_CERT_ALIAS_LN));
        if (childElement != null) {
            rampartConfig.setUserCertAlias(childElement.getText().trim());
        }

        childElement = element.getFirstChildWithName(new QName(RampartConfig.NS,
                                                               RampartConfig.ACTOR_LN));
        if (childElement != null) {
            rampartConfig.setActor(childElement.getText().trim());
        }

        childElement = element.getFirstChildWithName(new QName(RampartConfig.NS,
                                                               RampartConfig.MUST_UNDERSTAND_LN));
        if (childElement != null) {
            rampartConfig.setMustUnderstand(Integer.parseInt(childElement.getText().trim()));
        }

        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.ENCRYPTION_USER_LN));
        if (childElement != null) {
            rampartConfig.setEncryptionUser(childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.STS_ALIAS_LN));
        if (childElement != null) {
            rampartConfig.setStsAlias(childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.PW_CB_CLASS_LN));
        if (childElement != null) {
            rampartConfig.setPwCbClass(childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.POLICY_VALIDATOR_CB_CLASS_LN));
        if (childElement != null) {
            rampartConfig.setPolicyValidatorCbClass(childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.RAMPART_CONFIG_CB_CLASS_LN));
        if (childElement != null) {
            rampartConfig.setRampartConfigCbClass(childElement.getText().trim());
        }
                      
        // handle ssl config	
		childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.SSL_CONFIG));
        if (childElement != null) {            	            	
        	SSLConfig sslConfig = (SSLConfig)new SSLConfigBuilder().
        	                          build(childElement, 
        			                  factory);
            rampartConfig.setSSLConfig(sslConfig);
            
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.KERBEROS_CONFIG));
        if (childElement != null) {                             
            KerberosConfig krbConfig = (KerberosConfig)new KerberosConfigBuilder().
                                      build(childElement, 
                                      factory);
            rampartConfig.setKerberosConfig(krbConfig);
            
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.SIG_CRYPTO_LN));
        if (childElement != null) {
            rampartConfig.setSigCryptoConfig((CryptoConfig) factory
                    .build(childElement.getFirstElement()));
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.ENCR_CRYPTO_LN));
        if (childElement != null) {
            rampartConfig.setEncrCryptoConfig((CryptoConfig) factory
                    .build(childElement.getFirstElement()));
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.DEC_CRYPTO_LN));
        if (childElement != null) {
            rampartConfig.setDecCryptoConfig((CryptoConfig) factory
                    .build(childElement.getFirstElement()));
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.STS_CRYPTO_LN));
        if (childElement != null) {
            rampartConfig.setStsCryptoConfig((CryptoConfig) factory
                    .build(childElement.getFirstElement()));
        }

        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.TS_PRECISION_IN_MS_LN));
        if (childElement != null) {
            rampartConfig.setTimestampPrecisionInMilliseconds(childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.TS_TTL_LN));
        if (childElement != null) {
            rampartConfig.setTimestampTTL(childElement.getText().trim());
        }

        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.TS_MAX_SKEW_LN));
        if (childElement != null) {
            rampartConfig.setTimestampMaxSkew(childElement.getText().trim());
        }

        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.NONCE_LIFE_TIME));
        if (childElement != null) {
            rampartConfig.setNonceLifeTime(childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.TOKEN_STORE_CLASS_LN));
        if (childElement != null) {
            rampartConfig.setTokenStoreClass(childElement.getText().trim());
        }
        
		childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.OPTIMISE_PARTS));
        if (childElement != null) {
        	OptimizePartsConfig config = (OptimizePartsConfig)new OptimizePartsBuilder().
            build(childElement, factory);
        	rampartConfig.setOptimizeParts(config);
        }

        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.TIMESTAMP_STRICT_LN));
        if (childElement != null) {
            rampartConfig.setTimeStampStrict(childElement.getText().trim());
        }

        childElement = element.getFirstChildWithName(new QName(
                RampartConfig.NS, RampartConfig.OPTIMIZE_MSG_PROCESSING_TRANSPORT_BINDING));
        if (childElement != null) {
            rampartConfig.setOptimizeMessageProcessingForTransportBinding(
                    Boolean.parseBoolean(childElement.getText()));
        }

        return rampartConfig;
    }

    public QName[] getKnownElements() {
        return new QName[] {new QName(RampartConfig.NS, RampartConfig.RAMPART_CONFIG_LN)};
    }

}
