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

import org.apache.axiom.om.OMException;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.HandlerDescription;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.Handler;
import org.apache.axis2.namespace.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rampart.RampartConstants;
import org.apache.rampart.RampartEngine;
import org.apache.rampart.RampartException;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import javax.xml.namespace.QName;

/**
 * Rampart inflow handler.
 * This processes the incoming message and validates it against the effective
 * policy.
 */
public class RampartReceiver implements Handler {

    public static final String INCLUDE_FULL_WSSECURITYEXCEPTION_MESSAGE = "includeFullWSSecurityExceptionMessage";
    private static Log mlog = LogFactory.getLog(RampartConstants.MESSAGE_LOG);

    private static HandlerDescription EMPTY_HANDLER_METADATA =
        new HandlerDescription("default Handler");

    private HandlerDescription handlerDesc;

    public RampartReceiver() {
        this.handlerDesc = EMPTY_HANDLER_METADATA;
    }

    public void cleanup() {
    }

    public void init(HandlerDescription handlerdesc) {
        this.handlerDesc = handlerdesc;
    }

    public void flowComplete(MessageContext msgContext)
    {

    }

    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {

        if (!msgContext.isEngaged(WSSHandlerConstants.SECURITY_MODULE_NAME)) {
          return InvocationResponse.CONTINUE;
        }

        if(mlog.isDebugEnabled()){
        	mlog.debug("*********************** RampartReceiver received \n"
                    + msgContext.getEnvelope());
        }

        RampartEngine engine = new RampartEngine();
        Vector wsResult = null;
        try {
            wsResult = engine.process(msgContext);

        } catch (WSSecurityException e) {
            setFaultCodeAndThrowAxisFault(msgContext, e);
        } catch (WSSPolicyException e) {
            setFaultCodeAndThrowAxisFault(msgContext, e);
        } catch (RampartException e) {
            setFaultCodeAndThrowAxisFault(msgContext, e);
        }

        if(wsResult == null) {
          return InvocationResponse.CONTINUE;
        }

        Vector results = null;
        if ((results = (Vector) msgContext
                .getProperty(WSHandlerConstants.RECV_RESULTS)) == null) {
            results = new Vector();
            msgContext.setProperty(WSHandlerConstants.RECV_RESULTS, results);
        }
        WSHandlerResult rResult = new WSHandlerResult("", wsResult);
        results.add(0, rResult);

        SOAPHeader header = null;
        try {
            header = msgContext.getEnvelope().getHeader();
        } catch (OMException ex) {
            throw new AxisFault(
                    "RampartReceiver: cannot get SOAP header after security processing",
                    ex);
        }

        Iterator headers = header.getChildElements();

        SOAPHeaderBlock headerBlock = null;

        while (headers.hasNext()) { // Find the wsse header
            SOAPHeaderBlock hb = (SOAPHeaderBlock) headers.next();
            if (hb.getLocalName().equals(WSConstants.WSSE_LN)
                    && hb.getNamespace().getNamespaceURI().equals(WSConstants.WSSE_NS)) {
                headerBlock = hb;
                break;
            }
        }

        if(headerBlock != null) {
            headerBlock.setProcessed();
        }

        return InvocationResponse.CONTINUE;

    }


    public HandlerDescription getHandlerDesc() {
        return this.handlerDesc;
    }

    public String getName() {
        return "Apache Rampart inflow handler";
    }

    public Parameter getParameter(String name) {
        return this.handlerDesc.getParameter(name);
    }

    private void setFaultCodeAndThrowAxisFault(MessageContext msgContext, Exception e) throws AxisFault {

        msgContext.setProperty(RampartConstants.SEC_FAULT, Boolean.TRUE);
        String soapVersionURI =  msgContext.getEnvelope().getNamespace().getNamespaceURI();
        QName faultCode = null;
        /*
         * Get the faultCode from the thrown WSSecurity exception, if there is one
         */
        if (e instanceof WSSecurityException)
        {
        	faultCode = ((WSSecurityException)e).getFaultCode();
        }
        /*
         * Otherwise default to InvalidSecurity
         */
        if (faultCode == null)
        {
        	faultCode = new QName(WSConstants.INVALID_SECURITY.getNamespaceURI(),WSConstants.INVALID_SECURITY.getLocalPart(),"wsse");
        }

        if (soapVersionURI.equals(SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI) ) {

            String standardMsg = e.getMessage();
            Parameter parameter = getParameter(msgContext, INCLUDE_FULL_WSSECURITYEXCEPTION_MESSAGE);
            if (parameter == null
                    || (parameter != null
                        && parameter.getValue() instanceof String
                        && !Boolean.parseBoolean((String)parameter.getValue()))) {
                if (e instanceof WSSecurityException) {
                    //As WSSecurityException extends RemoteException, get getMessage will return nested exception and
                    // its error message, which should not be sent to the client. Sending the nested exception causes
                    // an unwanted information disclosure
                    standardMsg = standardMsg.split("; nested exception is:")[0];
                }
            }
            throw new AxisFault(faultCode,standardMsg,e);

        } else if (soapVersionURI.equals(SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI)) {

            List subfaultCodes = new ArrayList();
            subfaultCodes.add(faultCode);
            String standardMsg = e.getMessage();
            Parameter parameter = getParameter(msgContext, INCLUDE_FULL_WSSECURITYEXCEPTION_MESSAGE);
            if (parameter == null
                    || (parameter != null
                    && parameter.getValue() instanceof String
                    && !Boolean.parseBoolean((String)parameter.getValue()))) {
                if (e instanceof WSSecurityException) {
                    //As WSSecurityException extends RemoteException, get getMessage will return nested exception and
                    // its error message, which should not be sent to the client. Sending the nested exception causes
                    // an unwanted information disclosure
                    standardMsg = standardMsg.split("; nested exception is:")[0];
                }
            }
            AxisFault fault = new AxisFault(Constants.FAULT_SOAP12_SENDER, subfaultCodes, standardMsg, e);
            if (isApplicationError(e)) {
                fault.setFaultType(org.apache.axis2.Constants.APPLICATION_FAULT);
            }
            throw fault;
        }
    }

    /**
     * Return true if the passed Exception is an WSSecurityException and the error is an application error.
     *
     * @param e WSSecurity Exception that needs to be checked for application error.
     * @return True if the error code is > 0 and <= 10.
     */
    private boolean isApplicationError(Exception e) {

        if (e instanceof WSSecurityException) {
            int errorCode = ((WSSecurityException) e).getErrorCode();
            switch (errorCode) {
                case WSSecurityException.UNSUPPORTED_SECURITY_TOKEN:
                case WSSecurityException.UNSUPPORTED_ALGORITHM:
                case WSSecurityException.INVALID_SECURITY:
                case WSSecurityException.INVALID_SECURITY_TOKEN:
                case WSSecurityException.FAILED_AUTHENTICATION:
                case WSSecurityException.FAILED_CHECK:
                case WSSecurityException.SECURITY_TOKEN_UNAVAILABLE:
                case WSSecurityException.MESSAGE_EXPIRED:
                case WSSecurityException.FAILED_ENCRYPTION:
                case WSSecurityException.FAILED_SIGNATURE:
                    return true;
            }
        }
        return false;
    }

    /**
     * Returns the Parameter value for the given parameter name from available scope.
     *
     * @param msgContext The message context.
     * @param paramName  The name of the parameter
     * @return looked up parameter if it is available in the axis configuration. null if not found.
     */
    private Parameter getParameter(MessageContext msgContext, String paramName) {
        AxisConfiguration axisConfiguration = null;
        if (msgContext.getAxisMessage() != null) {
            axisConfiguration = msgContext.getAxisMessage().getAxisConfiguration();
        }
        if (axisConfiguration == null && msgContext.getConfigurationContext() != null) {
            axisConfiguration = msgContext.getConfigurationContext().getAxisConfiguration();
        }
        if (axisConfiguration != null) {
            return axisConfiguration.getParameter(paramName);
        }
        return null;
    }
}
