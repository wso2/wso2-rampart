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

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.context.OperationContext;
import org.apache.axis2.wsdl.WSDLConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rampart.RampartConstants;
import org.apache.rampart.util.Axis2Util;
import org.apache.rampart.util.HandlerParameterDecoder;
import org.apache.rampart.util.MessageOptimizer;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.util.Vector;

/**
 * @deprecated
 */
public class WSDoAllSender extends WSDoAllHandler {
    
    private static final Log log = LogFactory.getLog(WSDoAllSender.class);
    private static Log mlog = LogFactory.getLog(RampartConstants.MESSAGE_LOG);
    
    
    public WSDoAllSender() {
        super();
        inHandler = false;
    }
      
    public void processMessage(MessageContext msgContext) throws AxisFault {
        
              String useDoomValue = (String) getProperty(msgContext,
                WSSHandlerConstants.USE_DOOM);
        boolean useDoom = useDoomValue != null
                && Constants.VALUE_TRUE.equalsIgnoreCase(useDoomValue);
        
        RequestData reqData = new RequestData();
        try {
            //If the msgs are msgs to an STS then use basic WS-Sec
            processBasic(msgContext, useDoom, reqData);
            
        } catch (Exception e) {
            throw new AxisFault(e.getMessage(), e);
        }
        finally {
            if(reqData != null) {
                reqData.clear();
                reqData = null;
            }
        }  
        
        if(mlog.isDebugEnabled()){
        	mlog.debug("*********************** WSDoAllSender sent out \n"+msgContext.getEnvelope());
        }
    }
    
    /**
     * This will carryout the WS-Security related operations.
     * 
     * @param msgContext
     * @param useDoom
     * @throws WSSecurityException
     * @throws AxisFault
     */
    private void processBasic(MessageContext msgContext, boolean useDoom,
            RequestData reqData) throws WSSecurityException, AxisFault {
        boolean doDebug = log.isDebugEnabled();
        
        try {
            HandlerParameterDecoder.processParameters(msgContext,false);
        } catch (Exception e) {
            throw new AxisFault("Configureation error", e);
        }
        
        if (doDebug) {
            log.debug("WSDoAllSender: enter invoke()");
        }
        
        /*
         * Copy the RECV_RESULTS over to the current message context
         * - IF available 
         */
        OperationContext opCtx = msgContext.getOperationContext();
        MessageContext inMsgCtx;
        if(opCtx != null && 
                (inMsgCtx = opCtx.getMessageContext(WSDLConstants.MESSAGE_LABEL_IN_VALUE)) != null) {
            msgContext.setProperty(WSHandlerConstants.RECV_RESULTS, 
                    inMsgCtx.getProperty(WSHandlerConstants.RECV_RESULTS));
        }
        
        
        
        reqData.setNoSerialization(false);
        reqData.setMsgContext(msgContext);
        
        if (((getOption(WSSHandlerConstants.OUTFLOW_SECURITY)) == null) &&
                ((getProperty(msgContext, WSSHandlerConstants.OUTFLOW_SECURITY)) == null)) {
                
                if (msgContext.isServerSide() && 
                    ((getOption(WSSHandlerConstants.OUTFLOW_SECURITY_SERVER)) == null) &&
                    ((getProperty(msgContext, WSSHandlerConstants.OUTFLOW_SECURITY_SERVER)) == null)) {
                
                    return;
                } else if (((getOption(WSSHandlerConstants.OUTFLOW_SECURITY_CLIENT)) == null) &&
                        ((getProperty(msgContext, WSSHandlerConstants.OUTFLOW_SECURITY_CLIENT)) == null))  {
                    
                    return;
                }
            }
        
        Vector actions = new Vector();
        String action = null;
        if ((action = (String) getOption(WSSHandlerConstants.ACTION_ITEMS)) == null) {
            action = (String) getProperty(msgContext, WSSHandlerConstants.ACTION_ITEMS);
        }
        if (action == null) {
            throw new AxisFault("WSDoAllReceiver: No action items defined");
        }
        
        int doAction = WSSecurityUtil.decodeAction(action, actions);
        if (doAction == WSConstants.NO_SECURITY) {
            return;
        }
        
        /*
         * For every action we need a username, so get this now. The
         * username defined in the deployment descriptor takes precedence.
         */
        reqData.setUsername((String) getOption(WSHandlerConstants.USER));
        if (reqData.getUsername() == null || reqData.getUsername().length() == 0) {
            String username = (String) getProperty(reqData.getMsgContext(), WSHandlerConstants.USER);
            if (username != null) {
                reqData.setUsername(username);
            }
        }
        
        /*
         * Now we perform some set-up for UsernameToken and Signature
         * functions. No need to do it for encryption only. Check if
         * username is available and then get a passowrd.
         */
        if ((doAction & (WSConstants.SIGN | WSConstants.UT | WSConstants.UT_SIGN)) != 0) {
            /*
             * We need a username - if none throw an AxisFault. For
             * encryption there is a specific parameter to get a username.
             */
            if (reqData.getUsername() == null
                    || reqData.getUsername().length() == 0) {
                throw new AxisFault(
                "WSDoAllSender: Empty username for specified action");
            }
        }
        
        /*
         * Now get the SOAPEvelope from the message context and convert it
         * into a Document
         * 
         * Now we can perform our security operations on this request.
         */
        
        
        Document doc = null;
        /*
         * If the message context property conatins a document then this is
         * a chained handler.
         */
        if ((doc = (Document) ((MessageContext)reqData.getMsgContext())
                .getProperty(WSHandlerConstants.SND_SECURITY)) == null) {
            try {
                doc = Axis2Util.getDocumentFromSOAPEnvelope(msgContext.getEnvelope(), useDoom);
            } catch (WSSecurityException wssEx) {
                throw new AxisFault("WSDoAllReceiver: Error in converting to Document", wssEx);
            }
        }
        
        
        doSenderAction(doAction, doc, reqData, actions, !msgContext.isServerSide());
        
        /*
         * If noSerialization is false, this handler shall be the last (or
         * only) one in a handler chain. If noSerialization is true, just
         * set the processed Document in the transfer property. The next
         * Axis WSS4J handler takes it and performs additional security
         * processing steps.
         *
         */
        if (reqData.isNoSerialization()) {
            ((MessageContext)reqData.getMsgContext()).setProperty(WSHandlerConstants.SND_SECURITY,
                    doc);
        } else {
            if(useDoom) {
                msgContext.setEnvelope((SOAPEnvelope)doc.getDocumentElement());
            } else {
                msgContext.setEnvelope(Axis2Util.getSOAPEnvelopeFromDOMDocument(doc, useDoom));
            }
            ((MessageContext)reqData.getMsgContext()).setProperty(WSHandlerConstants.SND_SECURITY, null);
        }
        

        /**
         * If the optimizeParts parts are set then optimize them
         */
        String optimizeParts;
        
        if((optimizeParts = (String) getOption(WSSHandlerConstants.OPTIMIZE_PARTS)) == null) {
            optimizeParts = (String)
            getProperty(reqData.getMsgContext(), WSSHandlerConstants.OPTIMIZE_PARTS);
        }
        if(optimizeParts != null) {
            // Optimize the Envelope
            MessageOptimizer.optimize(msgContext.getEnvelope(),optimizeParts);
        }
        
        //Enable handler repetition
        Integer repeat;
        int repeatCount;
        if ((repeat = (Integer)getOption(WSSHandlerConstants.SENDER_REPEAT_COUNT)) == null) {
            repeat = (Integer)
            getProperty(reqData.getMsgContext(), WSSHandlerConstants.SENDER_REPEAT_COUNT);
        }
        
        repeatCount = repeat.intValue();
        
        //Get the current repetition from message context
        int repetition = this.getCurrentRepetition(msgContext);
        
        if(repeatCount > 0 && repetition < repeatCount) {
            
            reqData.clear();
            reqData = null;
            
            // Increment the repetition to indicate the next repetition
            // of the same handler
            repetition++;
            msgContext.setProperty(WSSHandlerConstants.CURRENT_REPETITON,
                    Integer.valueOf(repetition));
            
            this.invoke(msgContext);
        }
        
        if (doDebug) {
            log.debug("WSDoAllSender: exit invoke()");
        }
    }
    
}
