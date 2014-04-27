/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.wso2.carbon.policy.internal;

import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class Activator implements BundleActivator {
    
    private static final Log log = LogFactory.getLog(Activator.class);
    
    private static String[] builders = new String[] {
        "org.apache.ws.secpolicy11.builders.AlgorithmSuiteBuilder",
        "org.apache.ws.secpolicy11.builders.AsymmetricBindingBuilder",
        "org.apache.ws.secpolicy11.builders.EncryptedElementsBuilder",
        "org.apache.ws.secpolicy11.builders.EncryptedPartsBuilder",
        "org.apache.ws.secpolicy11.builders.InitiatorTokenBuilder",
        "org.apache.ws.secpolicy11.builders.LayoutBuilder",
        "org.apache.ws.secpolicy11.builders.ProtectionTokenBuilder",
        "org.apache.ws.secpolicy11.builders.RecipientTokenBuilder",
        "org.apache.ws.secpolicy11.builders.SignedElementsBuilder",
        "org.apache.ws.secpolicy11.builders.SignedPartsBuilder",
        "org.apache.ws.secpolicy11.builders.SupportingTokensBuilder",
        "org.apache.ws.secpolicy11.builders.TransportBindingBuilder",
        "org.apache.ws.secpolicy11.builders.TransportTokenBuilder",
        "org.apache.ws.secpolicy11.builders.UsernameTokenBuilder",
        "org.apache.ws.secpolicy11.builders.WSS10Builder",
        "org.apache.ws.secpolicy11.builders.WSS11Builder",
        "org.apache.ws.secpolicy11.builders.X509TokenBuilder",
        "org.apache.ws.secpolicy11.builders.Trust10Builder",
        "org.apache.ws.secpolicy11.builders.SecurityContextTokenBuilder",
        "org.apache.ws.secpolicy11.builders.SecureConversationTokenBuilder",
        "org.apache.ws.secpolicy11.builders.SymmetricBindingBuilder",
        "org.apache.ws.secpolicy11.builders.IssuedTokenBuilder",
        "org.apache.ws.secpolicy11.builders.RequiredElementsBuilder",
        "org.apache.ws.secpolicy11.builders.KerberosTokenBuilder",
        "org.apache.ws.secpolicy12.builders.AlgorithmSuiteBuilder",
        "org.apache.ws.secpolicy12.builders.AsymmetricBindingBuilder",
        "org.apache.ws.secpolicy12.builders.EncryptedElementsBuilder",
        "org.apache.ws.secpolicy12.builders.EncryptedPartsBuilder",
        "org.apache.ws.secpolicy12.builders.InitiatorTokenBuilder",
        "org.apache.ws.secpolicy12.builders.LayoutBuilder",
        "org.apache.ws.secpolicy12.builders.ProtectionTokenBuilder",
        "org.apache.ws.secpolicy12.builders.RecipientTokenBuilder",
        "org.apache.ws.secpolicy12.builders.SignedElementsBuilder",
        "org.apache.ws.secpolicy12.builders.SignedPartsBuilder",
        "org.apache.ws.secpolicy12.builders.SupportingTokensBuilder",
        "org.apache.ws.secpolicy12.builders.TransportBindingBuilder",
        "org.apache.ws.secpolicy12.builders.TransportTokenBuilder",
        "org.apache.ws.secpolicy12.builders.UsernameTokenBuilder",
        "org.apache.ws.secpolicy12.builders.WSS10Builder",
        "org.apache.ws.secpolicy12.builders.WSS11Builder",
        "org.apache.ws.secpolicy12.builders.X509TokenBuilder",
        "org.apache.ws.secpolicy12.builders.Trust13Builder",
        "org.apache.ws.secpolicy12.builders.SecurityContextTokenBuilder",
        "org.apache.ws.secpolicy12.builders.SecureConversationTokenBuilder",
        "org.apache.ws.secpolicy12.builders.SymmetricBindingBuilder",
        "org.apache.ws.secpolicy12.builders.IssuedTokenBuilder",
        "org.apache.ws.secpolicy12.builders.RequiredElementsBuilder",
        "org.apache.ws.secpolicy12.builders.ContentEncryptedElementsBuilder",
        "org.apache.ws.secpolicy12.builders.KerberosTokenBuilder"};

    public void start(BundleContext bundleContext) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("********* Security secpolicy ****");
        }
        
        Bundle bundle = bundleContext.getBundle();

        try {
            for (String buildeName : builders) {
                Class aClass = bundle.loadClass(buildeName.trim());
                AssertionBuilder builder = (AssertionBuilder) aClass.newInstance();
                QName[] knownElements = builder.getKnownElements();
                for (QName knownElement : knownElements) {
                    AssertionBuilderFactory.registerBuilder(knownElement, builder);
                }
            }

        }catch (Exception e) {
            log.error("Error initializing the security component", e);
            throw new Exception("initializationError", e);
        }
        
    }
    
    public void stop(BundleContext bundleContext) throws Exception {
        // TODO: Method implementation
    }
}

