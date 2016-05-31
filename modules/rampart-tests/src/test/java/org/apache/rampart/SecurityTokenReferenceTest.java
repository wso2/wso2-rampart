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
import junit.framework.TestCase;
import org.apache.rahas.TrustUtil;
import org.apache.rampart.util.Axis2Util;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.UUID;

public class SecurityTokenReferenceTest extends TestCase {

    public void testSecurityTokenReference() {

        try {
            Document doc = Axis2Util.getSecuredDocumentBuilder().newDocumentBuilder().newDocument();
            Element strElem = TrustUtil.createSecurityTokenReferenceWithTokenType(doc, UUID.randomUUID().toString(),
                    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID", "http://docs.oasis-open" +
                            ".org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
            System.out.println(strElem.getAttribute("wsse11:TokenType"));
            Assert.assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", strElem
                    .getAttribute("wsse11:TokenType"));
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
}
