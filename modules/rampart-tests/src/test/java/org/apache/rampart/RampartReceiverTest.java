/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.rampart;

import junit.framework.TestCase;
import org.apache.axiom.soap.impl.builder.StAXSOAPModelBuilder;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.context.ServiceGroupContext;
import org.apache.axis2.description.AxisModule;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.AxisServiceGroup;
import org.apache.axis2.description.OutInAxisOperation;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.Handler;
import org.apache.neethi.PolicyReference;
import org.apache.rampart.handler.RampartReceiver;

import java.io.FileInputStream;
import javax.xml.namespace.QName;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

public class RampartReceiverTest extends TestCase {

    public void testInvokeWithoutAxisMessage_NoSecurityHeader() throws Exception {
        RampartReceiver rampartReceiver = new RampartReceiver();
        MessageContext messageContext = initMsgCtxFromMessage("test-resources/policy/soapmessage-no-wss-header.xml");

        try {
            Handler.InvocationResponse invocationResponse = rampartReceiver.invoke(messageContext);

            fail("Should throw a security exception when called without security header");
        } catch (AxisFault af) {
            assertEquals("Missing wsse:Security header in request", af.getMessage());
        }
    }

    public void testInvokeWithoutAxisMessage_WithSecurityHeader() throws Exception {
        RampartReceiver rampartReceiver = new RampartReceiver();
        MessageContext messageContext = initMsgCtxFromMessage("test-resources/policy/soapmessage-with-wss-header.xml");
        rampartReceiver.invoke(messageContext);
    }

    /**
     * @throws XMLStreamException
     * @throws FactoryConfigurationError
     * @throws AxisFault
     */
    private MessageContext initMsgCtxFromMessage(String messageResource) throws Exception {
        MessageContext ctx = new MessageContext();

        AxisConfiguration axisConfiguration = new AxisConfiguration();
        PolicyReference policyReference = new PolicyReference();
        policyReference.setURI(this.getClass().getClassLoader()
                .getResource("./policy/rampart-policy-for-RampartReceiverTest.xml").toString());
        axisConfiguration.getPolicySubject().attachPolicyComponent(policyReference);

        AxisModule axismodule = new AxisModule();
        axismodule.setArchiveName("rampart");
        axisConfiguration.addModule(axismodule);
        axisConfiguration.engageModule("rampart");

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
        ctx.setAxisOperation(outInAxisOperation);
        Options options = new Options();
        options.setAction("urn:testOperation");
        ctx.setOptions(options);

        XMLStreamReader reader = XMLInputFactory.newInstance().
                createXMLStreamReader(new FileInputStream(messageResource));
        ctx.setEnvelope(new StAXSOAPModelBuilder(reader, null).getSOAPEnvelope());

        return ctx;
    }

}
