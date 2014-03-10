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
package org.apache.rahas;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class TokenRequestDispatcher {

    private TokenRequestDispatcherConfig config;
    
    private static Log mlog = LogFactory.getLog("org.apache.rampart.messages");
    private static Log log = LogFactory.getLog(TokenRequestDispatcher.class.getName());

    public TokenRequestDispatcher(TokenRequestDispatcherConfig config) throws TrustException {
        this.config = config;
    }

    public TokenRequestDispatcher(OMElement config) throws TrustException {
        this(TokenRequestDispatcherConfig.load(config));
    }

    public TokenRequestDispatcher(String configFilePath) throws TrustException {
        this(TokenRequestDispatcherConfig.load(configFilePath));
    }

    /**
     * Processes the incoming request and returns a SOAPEnvelope
     * @param inMsgCtx
     * @return The response SOAPEnvelope
     * @throws TrustException
     */
    public SOAPEnvelope handle(MessageContext inMsgCtx,
                               MessageContext outMsgCtx) throws TrustException {
        
    	if(mlog.isDebugEnabled()){
    		mlog.debug("*********************** TokenRequestDispatcher received \n"+inMsgCtx.getEnvelope());
    	}
        RahasData data = new RahasData(inMsgCtx);
        
        String reqType = data.getRequestType();
        String tokenType = data.getTokenType();
        if ((RahasConstants.WST_NS_05_02 + RahasConstants.REQ_TYPE_ISSUE).equals(reqType) ||
                (RahasConstants.WST_NS_05_12 + RahasConstants.REQ_TYPE_ISSUE).equals(reqType)) {
            log.debug("issue");
            TokenIssuer issuer;
            if (tokenType == null ||  tokenType.trim().length() == 0) {
                issuer = config.getDefaultIssuerInstace();
            } else {
                issuer = config.getIssuer(tokenType);
            }
            
            SOAPEnvelope response = issuer.issue(data);
            
            //set the response wsa/soap action in the out message context
            outMsgCtx.getOptions().setAction(issuer.getResponseAction(data));
            
            if(mlog.isDebugEnabled()){
        		mlog.debug("*********************** TokenRequestDispatcher sent out \n"+response);
        	}
            
            return response;
        } else if((RahasConstants.WST_NS_05_02 + RahasConstants.REQ_TYPE_VALIDATE).equals(reqType) ||
                (RahasConstants.WST_NS_05_12 + RahasConstants.REQ_TYPE_VALIDATE).equals(reqType)) {
            log.debug("validate");

            TokenValidator validator;
                if (tokenType == null ||  tokenType.trim().length() == 0) {
                    validator = config.getDefaultValidatorInstance();
                } else {
                    validator = config.getValidator(tokenType);
                }

                SOAPEnvelope response = validator.validate(data);

                outMsgCtx.getOptions().setAction(
                        TrustUtil.getActionValue(data.getVersion(),
                                RahasConstants.RSTR_ACTION_VALIDATE));

                return response;
        	
        	
        	
        } else if((RahasConstants.WST_NS_05_02 + RahasConstants.REQ_TYPE_RENEW).equals(reqType) ||
                (RahasConstants.WST_NS_05_12 + RahasConstants.REQ_TYPE_RENEW).equals(reqType)) {
            log.debug("renew");

            TokenRenewer renewer;
                if (tokenType == null ||  tokenType.trim().length() == 0) {
                    renewer = config.getDefaultRenewerInstance();
                } else {
                    renewer = config.getRenewer(tokenType);                                       
                }
                
                SOAPEnvelope response = renewer.renew(data);

                outMsgCtx.getOptions().setAction(
                        TrustUtil.getActionValue(data.getVersion(),
                                RahasConstants.RSTR_ACTION_RENEW));

                return response;    	
        	         
        } else if((RahasConstants.WST_NS_05_02 + RahasConstants.REQ_TYPE_CANCEL).equals(reqType) ||
                (RahasConstants.WST_NS_05_12 + RahasConstants.REQ_TYPE_CANCEL).equals(reqType)) {
            log.debug("cancel");
            TokenCanceler canceler = config.getDefaultCancelerInstance();
            SOAPEnvelope response = canceler.cancel(data);

            //set the response wsa/soap action in the out message context
            outMsgCtx.getOptions().setAction(canceler.getResponseAction(data));
            return response;
        } else {
            throw new TrustException(TrustException.INVALID_REQUEST);
        }
        
        

        
    }
    
    
    
}
