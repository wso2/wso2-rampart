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

import java.io.ByteArrayInputStream;
import java.util.Vector;
import java.util.ArrayList;
import java.security.cert.X509Certificate;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.builder.SOAPBuilder;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.engine.AxisEngine;
import org.apache.axis2.namespace.Constants;
import org.apache.neethi.Policy;
import org.apache.rampart.util.Axis2Util;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.handler.WSHandlerConstants;

import javax.xml.namespace.QName;

public class RampartEngineTest extends MessageBuilderTestBase {

    public RampartEngineTest(String name) {
        super(name);
    }

    public void testEmptySOAPMessage() throws Exception {

        try {
            MessageContext ctx = getMsgCtx();

            String policyXml = "test-resources/policy/rampart-asymm-binding-6-3des-r15.xml";
            Policy policy = this.loadPolicy(policyXml);

            ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

            RampartEngine engine = new RampartEngine();
            engine.process(ctx);
        }
        catch (RampartException e) {
            assertEquals("Expected rampart to complain about missing security header",
                         "Missing wsse:Security header in request", e.getMessage());
        }
    }

    public void testValidSOAPMessage() throws Exception {

        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-asymm-binding-6-3des-r15.xml";
        Policy policy = loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        // Building the SOAP envelope from the OMElement
        buildSOAPEnvelope(ctx);

        RampartEngine engine = new RampartEngine();
        Vector results = engine.process(ctx);

        /*
        The principle purpose of the test case is to verify that the above processes
        without throwing an exception. However, perform a minimal amount of validation on the
        results.
        */
        assertNotNull("RampartEngine returned null result", results);
        //verify cert was stored
        X509Certificate usedCert = null;
        for (int i = 0; i < results.size(); i++) {
            WSSecurityEngineResult wser = (WSSecurityEngineResult) results.get(i);
            Integer action = (Integer) wser.get(WSSecurityEngineResult.TAG_ACTION);
            if (action.intValue() == WSConstants.SIGN) {
                //the result is for the signature, which contains the used certificate
                usedCert = (X509Certificate) wser.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                break;
            }
        }
        assertNotNull("Result of processing did not include a certificate", usedCert);
    }

    public void testValidSOAP12Message() throws Exception {

        MessageContext ctx = getMsgCtx12();

        String policyXml = "test-resources/policy/rampart-asymm-binding-6-3des-r15.xml";
        Policy policy = loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        // Building the SOAP envelope from the OMElement
        buildSOAPEnvelope(ctx);

        RampartEngine engine = new RampartEngine();
        Vector results = engine.process(ctx);

        /*
        The principle purpose of the test case is to verify that the above processes
        without throwing an exception. However, perform a minimal amount of validation on the
        results.
        */
        assertNotNull("RampartEngine returned null result", results);
        //verify cert was stored
        X509Certificate usedCert = null;
        for (int i = 0; i < results.size(); i++) {
            WSSecurityEngineResult wser = (WSSecurityEngineResult) results.get(i);
            Integer action = (Integer) wser.get(WSSecurityEngineResult.TAG_ACTION);
            if (action.intValue() == WSConstants.SIGN) {
                //the result is for the signature, which contains the used certificate
                usedCert = (X509Certificate) wser.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                break;
            }
        }
        assertNotNull("Result of processing did not include a certificate", usedCert);
    }

    private void buildSOAPEnvelope(MessageContext ctx) throws Exception {
        SOAPBuilder soapBuilder = new SOAPBuilder();
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream inStream = new ByteArrayInputStream(env.toString().getBytes());
        env = (SOAPEnvelope) soapBuilder.processDocument(inStream, getContentTypeForEnvelope(env), ctx);
        ctx.setEnvelope(env);
    }
}
