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
package org.apache.rahas;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.description.AxisDescription;
import org.apache.axis2.description.AxisModule;
import org.apache.axis2.modules.Module;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;


public class Rahas implements Module {

    private static Log log = LogFactory.getLog(Rahas.class);

    private static TokenPersister tokenPersister = null;
    private static TokenStorage tokenStore = null;

    public void init(ConfigurationContext configurationContext, AxisModule axisModule)
            throws AxisFault {
    }

    public void engageNotify(AxisDescription axisDescription) throws AxisFault {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public boolean canSupportAssertion(Assertion assertion) {
        return false;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void applyPolicy(Policy policy, AxisDescription axisDescription) throws AxisFault {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void shutdown(ConfigurationContext configurationContext) throws AxisFault {
        if (tokenPersister != null && tokenStore != null) {
            try {
                tokenStore.handlePersistenceOnShutdown();
            } catch (TrustException e) {
                String errorMessage = "Error in token persistence when Rahas module shutting down.";
                log.error(errorMessage, e);
                throw new AxisFault(errorMessage, e);
            }
        }
    }

    public static void setPersistanceStorage(TokenPersister persister, TokenStorage storage) {
        if (tokenPersister == null) {
            tokenPersister = persister;
        }
        if (tokenStore == null) {
            tokenStore = storage;
        }
    }
}
