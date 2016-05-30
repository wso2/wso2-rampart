/*
 * Copyright 2004,2015 The Apache Software Foundation.
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

import junit.framework.Assert;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.rahas.TrustException;
import org.apache.rahas.client.STSClient;

public class SecurityTokenRequestTemplateTest extends MessageBuilderTestBase {

    public void testSecurityTokenRequestTemplateClone() {

        String tokenRequestTemplate = "<sp:RequestSecurityTokenTemplate xmlns:sp=\"http://schemas.xmlsoap" +
                ".org/ws/2005/07/securitypolicy\" xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">\n" +
                "<wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>\n" +
                "<wst:KeyType>http://schemas.xmlsoap.org/ws/2005/02/trust/Bearer</wst:KeyType>\n" +
                "<t:KeySize xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">256</t:KeySize>\n" +
                "<t:KeySizee xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">256</t:KeySizee>\n" +
                "</sp:RequestSecurityTokenTemplate>";

        String tokenType = "<wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2" +
                ".0</wst:TokenType>";

        try {
            ConfigurationContext configCtx = getMsgCtx().getConfigurationContext();
            STSClient client = new STSClient(configCtx);
            OMElement omElement = AXIOMUtil.stringToOM(tokenRequestTemplate);
            client.setRstTemplate(omElement);
            client.createIssueRequest("", "");
            Assert.assertTrue(omElement.toString().contains(tokenType));
        } catch (TrustException e) {
            fail(e.getMessage());
        } catch (Exception e) {
            fail(e.getMessage());
        }

    }
}
