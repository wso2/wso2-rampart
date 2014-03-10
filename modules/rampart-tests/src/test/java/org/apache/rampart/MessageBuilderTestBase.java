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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axiom.soap.impl.builder.StAXSOAPModelBuilder;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.context.ServiceGroupContext;
import org.apache.axis2.description.AxisMessage;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.AxisServiceGroup;
import org.apache.axis2.description.OutInAxisOperation;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.wsdl.WSDLConstants;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.ws.security.WSConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import java.io.FileInputStream;
import java.util.Iterator;

import junit.framework.TestCase;

public class MessageBuilderTestBase extends TestCase {

    public MessageBuilderTestBase() {
        super();
    }

    public MessageBuilderTestBase(String arg0) {
        super(arg0);
    }

    /**
     * @throws XMLStreamException
     * @throws FactoryConfigurationError
     * @throws AxisFault
     */
    protected MessageContext getMsgCtx() throws Exception {
        return initMsgCtxFromMessage("test-resources/policy/soapmessage.xml");
    }

    /**
     * Return a message context initialized with a SOAP 1.2 message.
     *
     * @throws XMLStreamException
     * @throws FactoryConfigurationError
     * @throws AxisFault
     */
    protected MessageContext getMsgCtx12() throws Exception {
        return initMsgCtxFromMessage("test-resources/policy/soapmessage.xml");
    }

    /**
     * @throws XMLStreamException
     * @throws FactoryConfigurationError
     * @throws AxisFault
     */
    private MessageContext initMsgCtxFromMessage(String messageResource) throws Exception {
        MessageContext ctx = new MessageContext();

        AxisConfiguration axisConfiguration = new AxisConfiguration();
        AxisService axisService = new AxisService("TestService");
        axisConfiguration.addService(axisService);
        AxisServiceGroup axisServiceGroup = new AxisServiceGroup();
        axisConfiguration.addServiceGroup(axisServiceGroup);
        ctx.setConfigurationContext(new ConfigurationContext(axisConfiguration));
        axisServiceGroup.addService(axisService);
        ServiceGroupContext gCtx = ctx.getConfigurationContext().createServiceGroupContext(axisServiceGroup);
        ServiceContext serviceContext = gCtx.getServiceContext(axisService);
        ctx.setServiceContext(serviceContext);
        ctx.setAxisService(axisService);
        OutInAxisOperation outInAxisOperation = new OutInAxisOperation(new QName("http://rampart.org", "test"));
        AxisMessage msg = new AxisMessage();
        outInAxisOperation.addMessage(msg,WSDLConstants.MESSAGE_LABEL_OUT_VALUE);
        outInAxisOperation.addMessage(msg,WSDLConstants.MESSAGE_LABEL_IN_VALUE);
        ctx.setAxisOperation(outInAxisOperation);
        ctx.setAxisMessage(msg);
        Options options = new Options();
        options.setAction("urn:testOperation");
        ctx.setOptions(options);

        XMLStreamReader reader =
                XMLInputFactory.newInstance().
                        createXMLStreamReader(new FileInputStream(messageResource));
        ctx.setEnvelope(new StAXSOAPModelBuilder(reader, null).getSOAPEnvelope());
        return ctx;
    }

    protected Policy loadPolicy(String xmlPath) throws Exception {
        StAXOMBuilder builder = new StAXOMBuilder(xmlPath);
        return PolicyEngine.getPolicy(builder.getDocumentElement());
    }

    protected void verifySecHeader(Iterator qnameList, SOAPEnvelope env) {
        Iterator secHeaderChildren =
                env.getHeader().
                        getFirstChildWithName(new QName(WSConstants.WSSE_NS,
                                                        WSConstants.WSSE_LN)).getChildElements();

        while (secHeaderChildren.hasNext()) {
            OMElement element = (OMElement) secHeaderChildren.next();
            if (qnameList.hasNext()) {
                if (!element.getQName().equals(qnameList.next())) {
                    fail("Incorrect Element" + element);
                }
            } else {
                fail("Extra child in the security header: " + element.toString());
            }
        }

        if (qnameList.hasNext()) {
            fail("Incorrect number of children in the security header: " +
                 "next expected element" + qnameList.next().toString());
        }
    }

    public String getContentTypeForEnvelope(SOAPEnvelope env) {
        String contentType = SOAP11Constants.SOAP_11_CONTENT_TYPE;  //default
        if (SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI.equals(env.getNamespace().getNamespaceURI())) {
            contentType = SOAP11Constants.SOAP_11_CONTENT_TYPE;
        }
        else if (SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI.equals(env.getNamespace().getNamespaceURI())) {
            contentType = SOAP12Constants.SOAP_12_CONTENT_TYPE;
        }
        return contentType;
    }

}
