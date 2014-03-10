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

package org.apache.rampart.samples.policy.sample06;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.Token;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.client.STSClient;
import org.apache.rampart.RampartMessageData;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.opensaml.XML;

import javax.xml.namespace.QName;

public class Client {

	public static void main(String[] args) throws Exception {

		if(args.length != 3) {
			System.out.println("Usage: $java Client endpoint_address client_repo_path policy_xml_path");
		}

		ConfigurationContext ctx = ConfigurationContextFactory.createConfigurationContextFromFileSystem(args[1], null);
		
	        ServiceClient client = new ServiceClient(ctx, null);
		
	        Options options = new Options();
	        options.setAction("urn:echo");
	        options.setTo(new EndpointReference(args[0]));
	        options.setProperty(RampartMessageData.KEY_RAMPART_POLICY,  loadPolicy(args[2]));
	        options.setSoapVersionURI(SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI);
	        client.setOptions(options);
	        
	        client.engageModule("addressing");
                client.engageModule("rampart");
                
                OMElement response = client.sendReceive(getPayload("Hello world1"));
                System.out.println("Response  : " + response);
	        

	}

    private static Policy loadPolicy(String xmlPath) throws Exception {
        StAXOMBuilder builder = new StAXOMBuilder(xmlPath);
        return PolicyEngine.getPolicy(builder.getDocumentElement());
    }
	
    private static OMElement getSAMLToken(OMElement resp) {
        OMElement rst = resp.getFirstChildWithName(new QName(RahasConstants.WST_NS_05_02,
                                                             RahasConstants.IssuanceBindingLocalNames.
                                                                     REQUESTED_SECURITY_TOKEN));
        OMElement elem = rst.getFirstChildWithName(new QName(XML.SAML_NS, "Assertion"));
        return elem;
    }

	
    private static OMElement getPayload(String value) {
	OMFactory factory = OMAbstractFactory.getOMFactory();
	OMNamespace ns = factory.createOMNamespace("http://sample06.policy.samples.rampart.apache.org","ns1");
	OMElement elem = factory.createOMElement("echo", ns);
	OMElement childElem = factory.createOMElement("param0", null);
	childElem.setText(value);
	elem.addChild(childElem);
	        
	return elem;
	
    }
	
    private static OMElement getRSTTemplate() throws Exception {
	OMFactory fac = OMAbstractFactory.getOMFactory();
	OMElement elem = fac.createOMElement(SP11Constants.REQUEST_SECURITY_TOKEN_TEMPLATE);
	TrustUtil.createTokenTypeElement(RahasConstants.VERSION_05_02, elem).setText(RahasConstants.TOK_TYPE_SAML_10);
	TrustUtil.createKeyTypeElement(RahasConstants.VERSION_05_02, elem, RahasConstants.KEY_TYPE_SYMM_KEY);
	TrustUtil.createKeySizeElement(RahasConstants.VERSION_05_02, elem, 256);
	return elem;
    }  

}
