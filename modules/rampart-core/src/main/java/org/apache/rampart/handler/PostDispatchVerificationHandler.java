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

package org.apache.rampart.handler;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMException;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axiom.soap.impl.dom.soap11.SOAP11HeaderBlockImpl;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.HandlerDescription;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.engine.Handler;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rampart.RampartMessageData;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.util.HandlerParameterDecoder;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.model.Binding;
import org.apache.ws.secpolicy.model.SupportingToken;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.handler.WSHandlerConstants;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

/**
 * Handler to verify the message security after dispatch
 *
 */
public class PostDispatchVerificationHandler implements Handler {

    private HandlerDescription handlerDesc;
    
    /**
     * @see org.apache.axis2.engine.Handler#cleanup()
     */
    public void cleanup() {
    }

    /**
     * @see org.apache.axis2.engine.Handler#flowComplete(org.apache.axis2.context.MessageContext)
     */
    public void flowComplete(MessageContext msgContext) {
    }

    /**
     * @see org.apache.axis2.engine.Handler#getHandlerDesc()
     */
    public HandlerDescription getHandlerDesc() {
        return this.handlerDesc;
    }

    /**
     * @see org.apache.axis2.engine.Handler#getName()
     */
    public String getName() {
        return "Post dispatch security verification handler";
    }

    /**
     * @see org.apache.axis2.engine.Handler#getParameter(java.lang.String)
     */
    public Parameter getParameter(String name) {
        return this.handlerDesc.getParameter(name);
    }

    /**
     * @see org.apache.axis2.engine.Handler#init(org.apache.axis2.description.HandlerDescription)
     */
    public void init(HandlerDescription handlerDesc) {
        this.handlerDesc = handlerDesc;
    }

    /**
     * @see org.apache.axis2.engine.Handler#invoke(org.apache.axis2.context.MessageContext)
     */
    public InvocationResponse invoke(MessageContext msgContext)
            throws AxisFault {
       if (!msgContext.isEngaged(WSSHandlerConstants.SECURITY_MODULE_NAME)) {
          return InvocationResponse.CONTINUE;
        }

        Policy policy = msgContext.getEffectivePolicy();

        if(msgContext.getProperty(RampartMessageData.KEY_RAMPART_POLICY) != null) {
            policy = (Policy)msgContext.getProperty(RampartMessageData.KEY_RAMPART_POLICY);
        }
        

        if(policy == null) {
            policy = msgContext.getEffectivePolicy();
        }
        
        if(policy == null) {
            Parameter param = msgContext.getParameter(RampartMessageData.KEY_RAMPART_POLICY);
            if(param != null) {
                OMElement policyElem = param.getParameterElement().getFirstElement();
                policy = PolicyEngine.getPolicy(policyElem);
            }
        }
        
        if(policy == null) {
            return InvocationResponse.CONTINUE;
        }
        
        Iterator alternatives = policy.getAlternatives();
        
        boolean securityPolicyPresent = false;
        if(alternatives.hasNext()) {
            List assertions = (List)alternatives.next();
            for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
                Assertion assertion = (Assertion) iterator.next();
                //Check for any *Binding assertion
                if (assertion instanceof Binding) {
                    securityPolicyPresent = true;
                    break;
                // There can be  security policies containing only supporting tokens    
                } else if (assertion instanceof SupportingToken) {
                    securityPolicyPresent = true; 
                    break;
                }
            }
        }
        
        
        
        if (securityPolicyPresent) {
            RampartPolicyData rpd = (RampartPolicyData)msgContext.
                                                getProperty(RampartMessageData.RAMPART_POLICY_DATA);
            // Security policy data has not been populated at the time of verification
            if (rpd == null ) {
                throw new AxisFault("InvalidSecurity");
            }
            
            boolean isInitiator = false;
            Parameter clientSideParam = msgContext.getAxisService().
                                                getParameter(RampartMessageData.PARAM_CLIENT_SIDE);
            if(clientSideParam != null) {
                isInitiator = true;
            }
            
            //Now check for security processing results if security policy is available
            if(RampartUtil.isSecHeaderRequired(rpd,isInitiator,true) && 
                                  msgContext.getProperty(WSHandlerConstants.RECV_RESULTS) == null) {
                throw new AxisFault("InvalidSecurity");
            }           
            
        }
    
        //Check for an empty security processing results when parameter based 
        //configuration is used
        if(msgContext.getParameter(WSSHandlerConstants.INFLOW_SECURITY) != null ||
                msgContext.getProperty(WSSHandlerConstants.INFLOW_SECURITY) != null) {
            if(msgContext.getProperty(WSHandlerConstants.RECV_RESULTS) == null) {
                    throw new AxisFault("InvalidSecurity");
            } else {
                if(((Vector)msgContext.getProperty(WSHandlerConstants.RECV_RESULTS)).size() == 0) {
                    throw new AxisFault("InvalidSecurity");
                }
            }
        }
        
        // If a security header is there and Rampart is engaged, it has to be processed.  
        // If it is not processed, there must have been a problem in picking the policy 
        
        SOAPHeaderBlock secHeader = getSecurityHeader(msgContext);
        
        if (secHeader != null && (secHeader.isProcessed() == false)) {
            throw new AxisFault("InvalidSecurity - Security policy not found");
        }
        
        return InvocationResponse.CONTINUE;
        
    }
    
    private SOAPHeaderBlock getSecurityHeader(MessageContext msgContext) throws AxisFault {
        
        SOAPHeader header = null;
        try {
            header = msgContext.getEnvelope().getHeader();
        } catch (OMException ex) {
            throw new AxisFault(
                "PostDispatchVerificationHandler: cannot get SOAP header after security processing",
                    ex);
        }
        
        if(header == null) {
            return null;
        }

        Iterator headers = header.getChildElements();

        SOAPHeaderBlock headerBlock = null;

        while (headers.hasNext()) { 
            // Find the wsse header
            SOAPHeaderBlock hb = (SOAPHeaderBlock) headers.next();
            if (hb.getLocalName().equals(WSConstants.WSSE_LN)
                    && hb.getNamespace().getNamespaceURI().equals(WSConstants.WSSE_NS)) {
                headerBlock = hb;
                break;
            }
        }
        
        return headerBlock;
        
        
    }

}
