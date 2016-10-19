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

import junit.framework.TestCase;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.integration.UtilServer;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;


public class RampartTest extends TestCase {

    public final static int PORT = UtilServer.TESTING_PORT;

    public RampartTest(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        UtilServer.start(Constants.TESTING_PATH + "rampart_service_repo" ,null);
    }
    

    protected void tearDown() throws Exception {
        UtilServer.stop();
    }

    private ServiceClient getServiceClientInstance() throws AxisFault {

        String repository = Constants.TESTING_PATH + "rampart_client_repo";

        ConfigurationContext configContext = ConfigurationContextFactory.
                createConfigurationContextFromFileSystem(repository, null);
        ServiceClient serviceClient = new ServiceClient(configContext, null);
        serviceClient.getOptions().setTimeOutInMilliSeconds(3*60*1000);

        serviceClient.engageModule("addressing");
        serviceClient.engageModule("rampart");

        return serviceClient;

    }

    public void testWithPolicy() {
        try {

            ServiceClient serviceClient = getServiceClientInstance();

            //TODO : figure this out !!
            boolean basic256Supported = false;
            
            if(basic256Supported) {
                System.out.println("\nWARNING: We are using key sizes from JCE " +
                        "Unlimited Strength Jurisdiction Policy !!!");
            }
            
            for (int i = 1; i <= 33; i++) { //<-The number of tests we have
                if(!basic256Supported && (i == 3 || i == 4 || i == 5)) {
                    //Skip the Basic256 tests
                    continue;
                }

                if(i == 25){
                    // Testcase - 25 is failing, for the moment skipping it.
                    continue;
                }
                Options options = new Options();
                
                if( i == 13 ) {
                    continue; // Can't test Transport binding with Simple HTTP Server
                    //Username token created with user/pass from options
                    //options.setUserName("alice");
                    //options.setPassword("password");
                }
                
                System.out.println("Testing WS-Sec: custom scenario " + i);
                options.setAction("urn:echo");
                options.setTo(new EndpointReference("http://127.0.0.1:" +
                                        PORT +  
                                        "/axis2/services/SecureService" + i));
                
                ServiceContext context = serviceClient.getServiceContext();
                context.setProperty(RampartMessageData.KEY_RAMPART_POLICY, 
                        loadPolicy("/rampart/policy/" + i + ".xml"));
                serviceClient.setOptions(options);
                
                if (i == 31) {
                    OMNamespace omNamespace = OMAbstractFactory.getOMFactory().createOMNamespace(
                            "http://sample.com", "myNs");
                    SOAPHeaderBlock header = OMAbstractFactory.getSOAP12Factory()
                            .createSOAPHeaderBlock("VitalHeader", omNamespace);
                    header.addChild(AXIOMUtil.stringToOM("<foo>This is a sample Header</foo>"));
                    serviceClient.addHeader(header);
                }
                
                // Invoking the serive in the TestCase-28 should fail. So handling it differently..
                if (i == 28 || i==34) {
                    try {
                        //Blocking invocation
                        serviceClient.sendReceive(getOMElement());
                        fail("Service Should throw an error..");

                    } catch (AxisFault axisFault) {
                        if (i==28) {
                            assertEquals("Unexpected encrypted data found, no encryption required", axisFault.getMessage());
                        } else {
                            System.out.println(axisFault.getMessage());
                        }
                    }
                }

                else{
                    //Blocking invocation
                    serviceClient.sendReceive(getEchoElement());
                }
            }

            System.out.println("--------------Testing negative scenarios----------------------------");

            for (int i = 1; i <= 22; i++) {
                if (!basic256Supported && (i == 3 || i == 4 || i == 5)) {
                    //Skip the Basic256 tests
                    continue;
                }
                Options options = new Options();

                if (i == 13) {
                    continue;
                }

                System.out.println("Testing WS-Sec: negative scenario " + i);
                options.setAction("urn:returnError");
                options.setTo(new EndpointReference("http://127.0.0.1:" +
                        PORT +
                        "/axis2/services/SecureService" + i));

                ServiceContext context = serviceClient.getServiceContext();
                context.setProperty(RampartMessageData.KEY_RAMPART_POLICY,
                        loadPolicy("/rampart/policy/" + i + ".xml"));
                serviceClient.setOptions(options);

                try {
                    //Blocking invocation
                    serviceClient.sendReceive(getOMElement());
                    fail("Service Should throw an error..");

                } catch (AxisFault axisFault) {
                    assertEquals("Testing negative scenarios with Apache Rampart. Intentional Exception", axisFault.getMessage());
                }
            }

            // TODO : uncomment this tests after identifying the root case for client timeouts
//            for (int i = 1; i <= 6; i++) { //<-The number of tests we have
//
//                if (i == 3 || i == 6) {
//                    continue; // Can't test Transport binding scenarios with Simple HTTP Server
//                }
//
//                Options options = new Options();
//                System.out.println("Testing WS-SecConv: custom scenario " + i);
//                options.setAction("urn:echo");
//                options.setTo(new EndpointReference("http://127.0.0.1:" + PORT + "/axis2/services/SecureServiceSC" + i));
//                options.setTimeOutInMilliSeconds(3*60*1000);
//
//                //Create a new service client instance for each secure conversation scenario
//                serviceClient = getServiceClientInstance();
//
//                serviceClient.getServiceContext().setProperty(RampartMessageData.KEY_RAMPART_POLICY, loadPolicy("/rampart/policy/sc-" + i + ".xml"));
//                serviceClient.setOptions(options);
//
//                //Blocking invocation
//                serviceClient.sendReceive(getEchoElement());
//                serviceClient.sendReceive(getEchoElement());
//
//                //Cancel the token
//                options.setProperty(RampartMessageData.CANCEL_REQUEST, Constants.VALUE_TRUE);
//                serviceClient.sendReceive(getEchoElement());
//
//                options.setProperty(RampartMessageData.CANCEL_REQUEST, Constants.VALUE_FALSE);
//                serviceClient.sendReceive(getEchoElement());
//                options.setProperty(RampartMessageData.CANCEL_REQUEST, Constants.VALUE_TRUE);
//                serviceClient.sendReceive(getEchoElement());
//                serviceClient.cleanupTransport();
//
//            }

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    private OMElement getEchoElement() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace omNs = fac.createOMNamespace(
                "http://example1.org/example1", "example1");
        OMElement method = fac.createOMElement("echo", omNs);
        OMElement value = fac.createOMElement("Text", omNs);
        value.addChild(fac.createOMText(value, "Testing Rampart with WS-SecPolicy"));
        method.addChild(value);

        return method;
    }

    private OMElement getOMElement() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace omNs = fac.createOMNamespace(
                "http://example1.org/example1", "example1");
        OMElement method = fac.createOMElement("returnError", omNs);
        OMElement value = fac.createOMElement("Text", omNs);
        value.addChild(fac.createOMText(value, "Testing Rampart with WS-SecPolicy"));
        method.addChild(value);

        return method;
    }

    private Policy loadPolicy(String xmlPath) throws Exception {
        StAXOMBuilder builder = new StAXOMBuilder(RampartTest.class.getResourceAsStream(xmlPath));
        return PolicyEngine.getPolicy(builder.getDocumentElement());
    }


}
