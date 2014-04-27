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

package org.wso2.carbon.rampart.internal;

import javax.xml.namespace.QName;

import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleActivator;
import java.io.File;

public class RampartActivator implements BundleActivator {

    private static String[] builders = new String[]{"org.apache.rampart.policy.builders.CryptoConfigBuilder",
                                                    "org.apache.rampart.policy.builders.RampartConfigBuilder",
                                                    "org.apache.rampart.policy.builders.SSLConfigBuilder",
                                                    "org.apache.rampart.policy.builders.KerberosConfigBuilder",
                                                    "org.apache.rampart.policy.builders.CryptoConfigBuilder",
                                                    "org.apache.rampart.policy.builders.RampartConfigBuilder",
                                                    "org.apache.rampart.policy.builders.SSLConfigBuilder",
                                                    "org.apache.rampart.policy.builders.KerberosConfigBuilder"};

    public void start(BundleContext bundleContext) throws Exception{
            Bundle bundle = bundleContext.getBundle();
            
            String carbonHome = System.getProperty("carbon.home");
            // jaas.conf location.
            System.setProperty("java.security.auth.login.config", carbonHome + File.separator + "repository"+
                    File.separator + "conf" + File.separator + "security" + File.separator + "jaas.conf");
            
            //Registering rampart policy builders
            for (String buildeName : builders) {
                Class aClass = bundle.loadClass(buildeName.trim());
                AssertionBuilder builder = (AssertionBuilder) aClass.newInstance();
                QName[] knownElements = builder.getKnownElements();
                for (QName knownElement : knownElements) {
                    AssertionBuilderFactory.registerBuilder(knownElement, builder);
                }
            }
    }

    public void stop(BundleContext context) throws Exception {
    }
}
