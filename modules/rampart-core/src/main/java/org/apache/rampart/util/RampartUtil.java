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

package org.apache.rampart.util;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.axiom.soap.*;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.axis2.client.Options;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.dataretrieval.DRConstants;
import org.apache.axis2.dataretrieval.client.MexClient;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.mex.MexConstants;
import org.apache.axis2.mex.MexException;
import org.apache.axis2.mex.om.Metadata;
import org.apache.axis2.mex.om.MetadataReference;
import org.apache.axis2.mex.om.MetadataSection;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.Token;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.client.STSClient;
import org.apache.rampart.PolicyBasedResultsValidator;
import org.apache.rampart.PolicyValidatorCallbackHandler;
import org.apache.rampart.RampartConfigCallbackHandler;
import org.apache.rampart.RampartConstants;
import org.apache.rampart.RampartException;
import org.apache.rampart.RampartMessageData;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.SupportingPolicyData;
import org.apache.rampart.policy.model.CryptoConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.*;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.message.WSSecBase;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.Constants;
import org.jaxen.JaxenException;
import org.jaxen.XPath;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.KeyGenerator;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.servlet.http.HttpServletRequest;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RampartUtil {

    private static final String CRYPTO_PROVIDER = "org.apache.ws.security.crypto.provider";
    private static Log log = LogFactory.getLog(RampartUtil.class);

    private static Map<String, CachedCrypto> cryptoStore = new ConcurrentHashMap<String, CachedCrypto>();

    private static class CachedCrypto {
        private Crypto crypto;
        private long creationTime;

        public CachedCrypto(Crypto crypto, long creationTime) {
            this.crypto = crypto;
            this.creationTime = creationTime;
        }
    }

    public static CallbackHandler getPasswordCB(RampartMessageData rmd) throws RampartException {

        MessageContext msgContext = rmd.getMsgContext();
        RampartPolicyData rpd = rmd.getPolicyData();

        return getPasswordCB(msgContext, rpd);
    }

    /**
     * @param msgContext
     * @param rpd
     * @return The <code>CallbackHandler</code> instance
     * @throws RampartException
     */
    public static CallbackHandler getPasswordCB(MessageContext msgContext, RampartPolicyData rpd) throws RampartException {

        CallbackHandler cbHandler;

        if (rpd.getRampartConfig() != null && rpd.getRampartConfig().getPwCbClass() != null) {

            String cbHandlerClass = rpd.getRampartConfig().getPwCbClass();
            ClassLoader classLoader = msgContext.getAxisService().getClassLoader();

            if (log.isDebugEnabled()) {
                log.debug("loading class : " + cbHandlerClass);
            }

            Class cbClass;
            try {
                cbClass = Loader.loadClass(classLoader, cbHandlerClass);
            } catch (ClassNotFoundException e) {
                throw new RampartException("cannotLoadPWCBClass",
                        new String[]{cbHandlerClass}, e);
            }
            try {
                cbHandler = (CallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new RampartException("cannotCreatePWCBInstance",
                        new String[]{cbHandlerClass}, e);
            }
        } else {
            cbHandler = (CallbackHandler) msgContext.getProperty(
                    WSHandlerConstants.PW_CALLBACK_REF);
            if(cbHandler == null) {
                Parameter param = msgContext.getParameter(
                        WSHandlerConstants.PW_CALLBACK_REF);
                if(param != null) {
                    cbHandler = (CallbackHandler)param.getValue();
                }
            }
        }

        return cbHandler;
    }

   /**
    * Returns an instance of PolicyValidatorCallbackHandler to be used to validate ws-security results.
    *
    * @param msgContext {@link MessageContext}
    * @param rpd {@link RampartPolicyData}
    * @return {@link PolicyValidatorCallbackHandler}
    * @throws RampartException RampartException
    */
   public static PolicyValidatorCallbackHandler getPolicyValidatorCB(MessageContext msgContext, RampartPolicyData rpd) throws RampartException {

       PolicyValidatorCallbackHandler cbHandler;

        if (rpd.getRampartConfig() != null && rpd.getRampartConfig().getPolicyValidatorCbClass() != null) {

            String cbHandlerClass = rpd.getRampartConfig().getPolicyValidatorCbClass();
            ClassLoader classLoader = msgContext.getAxisService().getClassLoader();

            if (log.isDebugEnabled()) {
                log.debug("loading class : " + cbHandlerClass);
            }

            Class cbClass;
            try {
                cbClass = Loader.loadClass(classLoader, cbHandlerClass);
            } catch (ClassNotFoundException e) {
                throw new RampartException("cannotLoadPolicyValidatorCbClass",
                        new String[]{cbHandlerClass}, e);
            }
            try {
                cbHandler = (PolicyValidatorCallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new RampartException("cannotCreatePolicyValidatorCallbackInstance",
                        new String[]{cbHandlerClass}, e);
            }

        } else { // Initialise default PolicyValidatorCallbackHandler...
            cbHandler = new PolicyBasedResultsValidator();
        }

        return cbHandler;
    }

   public static RampartConfigCallbackHandler getRampartConfigCallbackHandler(MessageContext msgContext,
           RampartPolicyData rpd) throws RampartException {

       RampartConfigCallbackHandler rampartConfigCB;

       if (rpd.getRampartConfig() != null && rpd.getRampartConfig().getRampartConfigCbClass() != null) {

           String cbHandlerClass = rpd.getRampartConfig().getRampartConfigCbClass();
           ClassLoader classLoader = msgContext.getAxisService().getClassLoader();

           if (log.isDebugEnabled()) {
               log.debug("loading class : " + cbHandlerClass);
           }

           Class cbClass;
           try {
               cbClass = Loader.loadClass(classLoader, cbHandlerClass);
           } catch (ClassNotFoundException e) {
               throw new RampartException("cannotLoadRampartConfigCallbackClass",
                       new String[]{cbHandlerClass}, e);
           }
           try {
               rampartConfigCB = (RampartConfigCallbackHandler) cbClass.newInstance();
           } catch (java.lang.Exception e) {
               throw new RampartException("cannotCreateRampartConfigCallbackInstance",
                       new String[]{cbHandlerClass}, e);
           }

           return rampartConfigCB;

       }

       return null;


   }



    /**
     * Perform a callback to get a password.
     * <p/>
     * The called back function gets an indication why to provide a password:
     * to produce a UsernameToken, Signature, or a password (key) for a given
     * name.
     */
    public static WSPasswordCallback performCallback(CallbackHandler cbHandler,
                                               String username,
                                               int doAction)
            throws RampartException {

        WSPasswordCallback pwCb;
        int reason = 0;

        switch (doAction) {
        case WSConstants.UT:
        case WSConstants.UT_SIGN:
                reason = WSPasswordCallback.USERNAME_TOKEN;
                break;
            case WSConstants.SIGN:
                reason = WSPasswordCallback.SIGNATURE;
                break;
            case WSConstants.ENCR:
                reason = WSPasswordCallback.KEY_NAME;
                break;
        }
        pwCb = new WSPasswordCallback(username, reason);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = pwCb;
        /*
        * Call back the application to get the password
        */
        try {
            cbHandler.handle(callbacks);
        } catch (Exception e) {
            throw new RampartException("pwcbFailed", e);
        }
        return pwCb;
    }

    /**
     * Create the <code>Crypto</code> instance for encryption using information
     * from the rampart configuration assertion
     *
     * @param config
     * @return The <code>Crypto</code> instance to be used for encryption
     * @throws RampartException
     */
    public static Crypto getEncryptionCrypto(RampartConfig config, ClassLoader loader)
            throws RampartException {

        log.debug("Loading encryption crypto");

        Crypto crypto = null;

        if (config != null && config.getEncrCryptoConfig() != null) {
            CryptoConfig cryptoConfig = config.getEncrCryptoConfig();
            String provider = cryptoConfig.getProvider();
            if (log.isDebugEnabled()) {
                log.debug("Using provider: " + provider);
            }
            Properties prop = cryptoConfig.getProp();
            prop.put(CRYPTO_PROVIDER, provider);

            String cryptoKey = null;
            String interval = null;
            if (cryptoConfig.isCacheEnabled()) {
                if (cryptoConfig.getCryptoKey() != null) {
                    cryptoKey = prop.getProperty(cryptoConfig.getCryptoKey());
                    interval = cryptoConfig.getCacheRefreshInterval();
                }
                else if(provider.equals(RampartConstants.MERLIN_CRYPTO_IMPL)){
                    cryptoKey = cryptoConfig.getProp().getProperty(RampartConstants.MERLIN_CRYPTO_IMPL_CACHE_KEY);
                }
            }


            if (cryptoKey != null) {
                // Crypto caching is enabled
                crypto = retrieveCryptoFromCache(cryptoKey.trim() + "#" + provider.trim(), interval);
            }

            if (crypto == null) {
                // cache miss
                crypto = CryptoFactory.getInstance(prop, loader);
                if (cryptoKey != null) {
                    // Crypto caching is enabled - cache the Crypto object
                    cacheCrypto(cryptoKey.trim() + "#" + provider.trim(), crypto);
                }
            }
        } else {
            log.debug("Trying the signature crypto info");
            crypto = getSignatureCrypto(config, loader);
        }
        return crypto;
    }

    /**
     * Create the <code>Crypto</code> instance for signature using information
     * from the rampart configuration assertion
     *
     * @param config
     * @return The <code>Crypto</code> instance to be used for signature
     * @throws RampartException
     */
    public static Crypto getSignatureCrypto(RampartConfig config, ClassLoader loader)
            throws RampartException {

        log.debug("Loading Signature crypto");

        Crypto crypto = null;

        if (config != null && config.getSigCryptoConfig() != null) {
            CryptoConfig cryptoConfig = config.getSigCryptoConfig();
            String provider = cryptoConfig.getProvider();
            if (log.isDebugEnabled()) {
                log.debug("Using provider: " + provider);
            }
            Properties prop = cryptoConfig.getProp();
            prop.put(CRYPTO_PROVIDER, provider);
            String cryptoKey = null;
            String interval = null;

            if (cryptoConfig.isCacheEnabled()) {
                if (cryptoConfig.getCryptoKey() != null) {
                    cryptoKey = prop.getProperty(cryptoConfig.getCryptoKey());
                    interval = cryptoConfig.getCacheRefreshInterval();
                }
                else if(provider.equals(RampartConstants.MERLIN_CRYPTO_IMPL)){
                    cryptoKey = cryptoConfig.getProp().getProperty(RampartConstants.MERLIN_CRYPTO_IMPL_CACHE_KEY);
                }
            }

            if (cryptoKey != null) {
                // cache enabled
                crypto = retrieveCryptoFromCache(cryptoKey.trim() + "#" + provider.trim(), interval);
            }

            if (crypto == null) {
                // cache miss
                crypto = CryptoFactory.getInstance(prop, loader);
                if (cryptoKey != null) {
                    // cache enabled - let's cache
                    cacheCrypto(cryptoKey.trim() + "#" + provider.trim(), crypto);
                }
            }
        }
        return crypto;
    }


    /**
     * figureout the key identifier of a give X509Token
     * @param token
     * @return The key identifier of a give X509Token
     * @throws RampartException
     */
    public static int getKeyIdentifier(X509Token token) throws RampartException {
        if (token.isRequireIssuerSerialReference()) {
            return WSConstants.ISSUER_SERIAL;
        } else if (token.isRequireThumbprintReference()) {
            return WSConstants.THUMBPRINT_IDENTIFIER;
        } else if (token.isRequireEmbeddedTokenReference()) {
            return WSConstants.BST_DIRECT_REFERENCE;
        } else {
            throw new RampartException(
                    "unknownKeyRefSpeficier");

        }
    }

    /**
     * Process a give issuer address element and return the address.
     * @param issuerAddress
     * @return The address of an issuer address element
     * @throws RampartException If the issuer address element is malformed.
     */
    public static String processIssuerAddress(OMElement issuerAddress)
        throws RampartException {

    	if(issuerAddress == null){
    		throw new RampartException("invalidIssuerAddress",
    		                           new String[] { "Issuer address null" });
    	}

    	if(issuerAddress.getText() == null || "".equals(issuerAddress.getText())) {
    		throw new RampartException("invalidIssuerAddress",
    		                           new String[] { issuerAddress.toString() });
        }

    	return issuerAddress.getText().trim();
    }

    /**
     * Retrieve policy using metadata reference
     * <wsa:Metadata xmlns:wsa="http://www.w3.org/2005/08/addressing">
     *  <mex:Metadata
     *       xmlns:mex="http://schemas.xmlsoap.org/ws/2004/09/mex"
     *       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
     *           <mex:MetadataSection>
     *                  <mex:MetadataReference>
     *                      <wsa:Address>http://address/of/mex/service</wsa:Address>
     *                  </mex:MetadataReference>
     *           </mex:MetadataSection>
     *  </mex:Metadata>
     * </wsa:Metadata>
     * @param mex Metadata element
     * @return Policy from the mex service
     */
    public static Policy getPolicyFromMetadataRef(OMElement mex) throws RampartException {

        try {
            Metadata metadata = new Metadata();
            metadata.fromOM(mex.getFirstElement());

            MetadataSection[] metadataSections = metadata.getMetadatSections();
            MetadataReference reference = metadataSections[0].getMetadataReference();

            MexClient serviceClient = new MexClient();

            Options options = serviceClient.getOptions();
            options.setTo(reference.getEPR());
            options.setAction(DRConstants.SPEC.Actions.GET_METADATA_REQUEST);

            OMElement request = serviceClient.setupGetMetadataRequest(
                                                        MexConstants.SPEC.DIALECT_TYPE_POLICY,null);
            OMElement result = serviceClient.sendReceive(request);

            metadata.fromOM(result);
            MetadataSection[] mexSecs =  metadata.getMetadataSection(MexConstants.SPEC.DIALECT_TYPE_POLICY, null);
            OMElement policyElement = (OMElement) mexSecs[0].getInlineData();

            return PolicyEngine.getPolicy(policyElement);


        } catch (MexException e) {
            throw new RampartException("Error Retrieving the policy from mex", e);
        } catch (AxisFault e) {
            throw new RampartException("Error Retrieving the policy from mex", e);
        }

    }

    public static Policy addRampartConfig (RampartMessageData rmd, Policy policy) {

        RampartConfig servicRampConf = rmd.getPolicyData().getRampartConfig();
        RampartConfig stsRampConf = new RampartConfig();

        //TODO copy all the properties of service ramp conf to sts ramp conf
        stsRampConf.setUser(servicRampConf.getUser());
        stsRampConf.setSigCryptoConfig(servicRampConf.getSigCryptoConfig());
        stsRampConf.setPwCbClass(servicRampConf.getPwCbClass());

        stsRampConf.setEncryptionUser(servicRampConf.getStsAlias());
        stsRampConf.setEncrCryptoConfig(servicRampConf.getStsCryptoConfig());

        policy.addAssertion(stsRampConf);

        return policy;

    }


    public static OMElement createRSTTempalteForSCT(int conversationVersion,
            int wstVersion) throws RampartException {
        try {
            log.debug("Creating RSTTemplate for an SCT request");
            OMFactory fac = OMAbstractFactory.getOMFactory();

            OMNamespace wspNs = fac.createOMNamespace(SPConstants.P_NS, "wsp");
            OMElement rstTempl = fac.createOMElement(
                    SPConstants.REQUEST_SECURITY_TOKEN_TEMPLATE,
                    wspNs);

            //Create TokenType element and set the value
            OMElement tokenTypeElem = TrustUtil.createTokenTypeElement(
                    wstVersion, rstTempl);
            String tokenType = ConversationConstants
                    .getWSCNs(conversationVersion)
                    + ConversationConstants.TOKEN_TYPE_SECURITY_CONTEXT_TOKEN;
            tokenTypeElem.setText(tokenType);

            return rstTempl;
        } catch (TrustException e) {
            throw new RampartException("errorCreatingRSTTemplateForSCT", e);
        } catch (ConversationException e) {
            throw new RampartException("errorCreatingRSTTemplateForSCT", e);
        }
    }


    public static int getTimeToLive(RampartMessageData messageData) {

        RampartConfig rampartConfig = messageData.getPolicyData().getRampartConfig();
        if (rampartConfig != null) {
            String ttl = rampartConfig.getTimestampTTL();
            int ttl_i = 0;
            if (ttl != null) {
                try {
                    ttl_i = Integer.parseInt(ttl);
                } catch (NumberFormatException e) {
                    ttl_i = messageData.getTimeToLive();
                }
            }
            if (ttl_i <= 0) {
                ttl_i = messageData.getTimeToLive();
            }
            return ttl_i;
        } else {
            return RampartConfig.DEFAULT_TIMESTAMP_TTL;
        }
    }

    public static int getTimestampMaxSkew(RampartMessageData messageData) {

        RampartConfig rampartConfig = messageData.getPolicyData().getRampartConfig();
        if (rampartConfig != null) {
            String maxSkew = rampartConfig.getTimestampMaxSkew();
            int maxSkew_i = 0;
            if (maxSkew != null) {
                try {
                    maxSkew_i = Integer.parseInt(maxSkew);
                } catch (NumberFormatException e) {
                    maxSkew_i = messageData.getTimestampMaxSkew();
                }
            }
            if (maxSkew_i < 0) {
                maxSkew_i = 0;
            }
            return maxSkew_i;
        } else {
            return RampartConfig.DEFAULT_TIMESTAMP_MAX_SKEW;
        }
    }

    /**
     * Obtain a security context token.
     * @param rmd
     * @param secConvTok
     * @return Return the SecurityContextidentifier of the token
     * @throws TrustException
     * @throws RampartException
     */
    public static String getSecConvToken(RampartMessageData rmd,
            SecureConversationToken secConvTok) throws TrustException,
            RampartException {
        String action = TrustUtil.getActionValue(
                rmd.getWstVersion(),
                RahasConstants.RST_ACTION_SCT);

        // Get sts epr
        OMElement issuerEpr = secConvTok.getIssuerEpr();
        String issuerEprAddress = rmd.getMsgContext().getTo().getAddress();
        if(issuerEpr != null) {
            issuerEprAddress = RampartUtil.processIssuerAddress(issuerEpr);
        }

        //Find SC version
        int conversationVersion = rmd.getSecConvVersion();

        OMElement rstTemplate = RampartUtil.createRSTTempalteForSCT(
                conversationVersion,
                rmd.getWstVersion());

        Policy stsPolicy = null;

        //Try boot strap policy
        Policy bsPol = secConvTok.getBootstrapPolicy();

        if(bsPol != null) {
            log.debug("BootstrapPolicy found");
            bsPol.addAssertion(rmd.getPolicyData().getRampartConfig());
            //copy the <wsoma:OptimizedMimeSerialization/> to BootstrapPolicy
            if (rmd.getPolicyData().getMTOMAssertion() != null) {
              bsPol.addAssertion(rmd.getPolicyData().getMTOMAssertion());
            }
            stsPolicy = bsPol;
        } else {
            //No bootstrap policy use issuer policy
            log.debug("No bootstrap policy, using issuer policy");
            stsPolicy = rmd.getPolicyData().getIssuerPolicy();
        }

        String id = getToken(rmd, rstTemplate,
                issuerEprAddress, action, stsPolicy);

        if (log.isDebugEnabled()) {
            log.debug("SecureConversationToken obtained: id=" + id);
        }
        return id;
    }


    /**
     * Obtain an issued token.
     * @param rmd
     * @param issuedToken
     * @return The identifier of the issued token
     * @throws RampartException
     */
    public static String getIssuedToken(RampartMessageData rmd,
            IssuedToken issuedToken) throws RampartException {

        try {

            //TODO : Provide the overriding mechanism to provide a custom way of 
            //obtaining a token

            String action = TrustUtil.getActionValue(rmd.getWstVersion(),
                    RahasConstants.RST_ACTION_ISSUE);

            // Get sts epr
            String issuerEprAddress = RampartUtil.processIssuerAddress(issuedToken
                    .getIssuerEpr());

            OMElement rstTemplate = issuedToken.getRstTemplate();

            // Get STS policy
            Policy stsPolicy = (Policy)rmd.getMsgContext().getProperty(RampartMessageData.RAMPART_STS_POLICY);

            if( stsPolicy == null && issuedToken.getIssuerMex() != null) {
                stsPolicy = RampartUtil.getPolicyFromMetadataRef(issuedToken.getIssuerMex());
                RampartUtil.addRampartConfig(rmd, stsPolicy);
            }

            String id = getToken(rmd, rstTemplate, issuerEprAddress, action,
                    stsPolicy);

            if (log.isDebugEnabled()) {
                log.debug("Issued token obtained: id=" + id);
            }
            return id;
        } catch (TrustException e) {
            throw new RampartException("errorInObtainingToken", e);
        }
    }

    /**
     * Request a token.
     * @param rmd
     * @param rstTemplate
     * @param issuerEpr
     * @param action
     * @param issuerPolicy
     * @return Return the identifier of the obtained token
     * @throws RampartException
     */
    public static String getToken(RampartMessageData rmd, OMElement rstTemplate,
            String issuerEpr, String action, Policy issuerPolicy) throws RampartException {

        try {
            //First check whether the user has provided the token
            MessageContext msgContext = rmd.getMsgContext();
            String customTokeId = (String) msgContext
                    .getProperty(RampartMessageData.KEY_CUSTOM_ISSUED_TOKEN);
            if(customTokeId != null) {
                return customTokeId;
            } else {

                Axis2Util.useDOOM(false);

                STSClient client = new STSClient(rmd.getMsgContext()
                        .getConfigurationContext());
                // Set request action
                client.setAction(action);

                client.setVersion(rmd.getWstVersion());

                client.setRstTemplate(rstTemplate);

                // Set crypto information
                Crypto crypto = RampartUtil.getSignatureCrypto(rmd.getPolicyData().getRampartConfig(),
                        rmd.getMsgContext().getAxisService().getClassLoader());
                CallbackHandler cbh = RampartUtil.getPasswordCB(rmd);
                client.setCryptoInfo(crypto, cbh);

                // Get service policy
                Policy servicePolicy = rmd.getServicePolicy();

                // Get service epr
                String servceEprAddress = rmd.getMsgContext()
                        .getOptions().getTo().getAddress();

                //If addressing version can be found set it
                Object addrVersionNs = msgContext.getProperty(AddressingConstants.WS_ADDRESSING_VERSION);
                if(addrVersionNs != null) {
                    client.setAddressingNs((String)addrVersionNs);
                }

                Options options = new Options();

                options.setUserName(rmd.getMsgContext().getOptions().getUserName());
                options.setPassword(rmd.getMsgContext().getOptions().getPassword());

                if (msgContext.getProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER) != null) {
                    Protocol protocolHandler =
                        (Protocol)msgContext.getProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER);;
                    options.setProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER, protocolHandler);
                }

                if (msgContext.getParameter(WSHandlerConstants.PW_CALLBACK_REF) != null ) {
                    Parameter pwCallback = msgContext.getParameter(WSHandlerConstants.PW_CALLBACK_REF);
                    client.addParameter(pwCallback);
                }

                client.setOptions(options);

                //Set soap version
                if (msgContext.isSOAP11()) {
                    client.setSoapVersion(SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI);
                } else {
                    client.setSoapVersion(SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI);
                }


                //Make the request
                org.apache.rahas.Token rst =
                    client.requestSecurityToken(servicePolicy,
                                                issuerEpr,
                                                issuerPolicy,
                                                servceEprAddress);

                //Add the token to token storage
                rst.setState(Token.ISSUED);
                rmd.getTokenStorage().add(rst);
                Axis2Util.useDOOM(true);
                return rst.getId();
            }
        } catch (Exception e) {
            throw new RampartException("errorInObtainingToken", e);
        }
    }

    public static String getSoapBodyId(SOAPEnvelope env) {
        return addWsuIdToElement(env.getBody());
    }

    public static String addWsuIdToElement(OMElement elem) {
        String id;

        //first try to get the Id attr
        OMAttribute idAttr = elem.getAttribute(new QName("Id"));
        if(idAttr == null) {
            //then try the wsu:Id value
            idAttr = elem.getAttribute(new QName(WSConstants.WSU_NS, "Id"));
        }

        if(idAttr != null) {
            id = idAttr.getAttributeValue();
        } else {
            //Add an id
            OMNamespace ns = elem.getOMFactory().createOMNamespace(
                    WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
            id = "Id-" + elem.hashCode();
            idAttr = elem.getOMFactory().createOMAttribute("Id", ns, id);
            elem.addAttribute(idAttr);
        }

        return id;
    }

    public static Element appendChildToSecHeader(RampartMessageData rmd,
            OMElement elem) {
        return appendChildToSecHeader(rmd, (Element)elem);
    }

    public static Element appendChildToSecHeader(RampartMessageData rmd,
            Element elem) {
        Element secHeaderElem = rmd.getSecHeader().getSecurityHeader();
        Node node = secHeaderElem.getOwnerDocument().importNode(
                        elem, true);
        return (Element)secHeaderElem.appendChild(node);
    }

    public static Element insertSiblingAfter(RampartMessageData rmd,
            Element child, Element sibling) {
        if (child == null) {
            return appendChildToSecHeader(rmd, sibling);
        } else {
            if (child.getOwnerDocument().equals(sibling.getOwnerDocument())) {

                if (child.getParentNode() == null
                        && !child.getLocalName().equals("UsernameToken")) {
                    rmd.getSecHeader().getSecurityHeader().appendChild(child);
                }
                ((OMElement) child).insertSiblingAfter((OMElement) sibling);
                return sibling;
            } else {
                Element newSib = (Element) child.getOwnerDocument().importNode(
                        sibling, true);
                ((OMElement) child).insertSiblingAfter((OMElement) newSib);
                return newSib;
            }
        }
    }

    public static Element insertSiblingBefore(RampartMessageData rmd, Element child, Element sibling) {
        if(child == null) {
            return appendChildToSecHeader(rmd, sibling);
        } else {
            if(child.getOwnerDocument().equals(sibling.getOwnerDocument())) {
                ((OMElement)child).insertSiblingBefore((OMElement)sibling);
                return sibling;
            } else {
                Element newSib = (Element)child.getOwnerDocument().importNode(sibling, true);
                ((OMElement)child).insertSiblingBefore((OMElement)newSib);
                return newSib;
            }
        }

    }

    public static Vector getEncryptedParts(RampartMessageData rmd) {
		RampartPolicyData rpd = rmd.getPolicyData();
		SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
        Set namespaces = rmd.getDeclaredNamespaces();
        if(namespaces == null){
            namespaces = RampartUtil.findAllPrefixNamespaces(rmd.getMsgContext().getEnvelope(),
                    rpd.getDeclaredNamespaces());
        }
		Vector encryptedPartsElements = getPartsAndElements(false, envelope,
				rpd.isEncryptBody() && !rpd.isEncryptBodyOptional(), rpd
						.getEncryptedParts(), rpd.getEncryptedElements(), namespaces);
		return getContentEncryptedElements(encryptedPartsElements, envelope,
				rpd.getContentEncryptedElements(), namespaces);
	}

	public static Vector getSignedParts(RampartMessageData rmd) {
		RampartPolicyData rpd = rmd.getPolicyData();
		SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
        Set namespaces = rmd.getDeclaredNamespaces();
        if(namespaces == null){
            namespaces = RampartUtil.findAllPrefixNamespaces(rmd.getMsgContext().getEnvelope(),
                    rpd.getDeclaredNamespaces());
        }

        //"signAllHeaders" indicates that all the headers should be signed.
        if (rpd.isSignAllHeaders()) {
            Iterator childHeaders = envelope.getHeader().getChildElements();
            while (childHeaders.hasNext()) {
               OMElement hb = (OMElement) childHeaders.next();
                if (!(hb.getLocalName().equals(WSConstants.WSSE_LN)
                        && hb.getNamespace().getNamespaceURI().equals(WSConstants.WSSE_NS))) {
                    rpd.addSignedPart(hb.getNamespace().getNamespaceURI(),hb.getLocalName());
                }
           }
        }

		return getPartsAndElements(true, envelope, rpd.isSignBody()
				&& !rpd.isSignBodyOptional(), rpd.getSignedParts(), rpd
				.getSignedElements(), namespaces);
	}

	public static Vector getSupportingEncryptedParts(RampartMessageData rmd,
			SupportingPolicyData rpd) {
		SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
        Set namespaces = rmd.getDeclaredNamespaces();
        if(namespaces == null){
            namespaces = RampartUtil.findAllPrefixNamespaces(rmd.getMsgContext().getEnvelope(),
                    rpd.getDeclaredNamespaces());
        }
		return getPartsAndElements(false, envelope, rpd.isEncryptBody()
				&& !rpd.isEncryptBodyOptional(), rpd.getEncryptedParts(), rpd
				.getEncryptedElements(), namespaces);
	}

	public static Vector getSupportingSignedParts(RampartMessageData rmd,
			SupportingPolicyData rpd) {
		SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
        Set namespaces = rmd.getDeclaredNamespaces();
        if(namespaces == null){
            namespaces = RampartUtil.findAllPrefixNamespaces(rmd.getMsgContext().getEnvelope(),
                    rpd.getDeclaredNamespaces());
        }
		return getPartsAndElements(true, envelope, rpd.isSignBody()
				&& !rpd.isSignBodyOptional(), rpd.getSignedParts(), rpd
				.getSignedElements(), namespaces);
	}

    public static Set findAllPrefixNamespaces(OMElement currentElement, HashMap decNamespacess)
    {
    	Set results = new HashSet();

    	//Find declared namespaces
    	findPrefixNamespaces(currentElement,results);

    	//Get all default namespaces
    	List defaultNamespaces = getDefaultPrefixNamespaces(currentElement.getOMFactory());
    	for (Iterator iterator = defaultNamespaces.iterator(); iterator
                .hasNext();) {
            OMNamespace ns = (OMNamespace) iterator.next();
            results.add(ns);
        }

    	for ( Iterator iterator = decNamespacess.keySet().iterator(); iterator.hasNext();) {
    	    String prefix  = (String) iterator.next();
    	    String ns = (String) decNamespacess.get(prefix);
    	    OMFactory omFactory = currentElement.getOMFactory();
    	    OMNamespace namespace = omFactory.createOMNamespace(ns, prefix);
    	    results.add(namespace);

    	}

    	return results;
    }

    private static void findPrefixNamespaces(OMElement e, Set results)
    {

	    	Iterator iter = e.getAllDeclaredNamespaces();

	    	if (iter!=null)
	    	{
	    		while (iter.hasNext())
	    				results.add(iter.next());
	    	}

	    	Iterator children = e.getChildElements();

	    	while (children.hasNext())
	    	{
	    		findPrefixNamespaces((OMElement)children.next(), results);
	    	}
    }

    private static List getDefaultPrefixNamespaces(OMFactory factory)
    {
    	List namespaces = new ArrayList();

    	// put default namespaces here (sp, soapenv, wsu, etc...)
    	namespaces.add(factory.createOMNamespace(WSConstants.ENC_NS, WSConstants.ENC_PREFIX));
    	namespaces.add(factory.createOMNamespace(WSConstants.SIG_NS, WSConstants.SIG_PREFIX));
    	namespaces.add(factory.createOMNamespace(WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX));
    	namespaces.add(factory.createOMNamespace(WSConstants.WSU_NS, WSConstants.WSU_PREFIX));

    	return namespaces;

    }

    public static Vector getContentEncryptedElements (Vector encryptedPartsElements, SOAPEnvelope envelope,Vector elements, Set namespaces ) {

        Iterator elementsIter = elements.iterator();
        while (elementsIter.hasNext())
        {
                String expression = (String)elementsIter.next();
                try {
                                XPath xp = new AXIOMXPath(expression);
                                Iterator nsIter = namespaces.iterator();

                                while (nsIter.hasNext())
                                {
                                        OMNamespace tmpNs = (OMNamespace)nsIter.next();
                                        xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
                                }

                                List selectedNodes = xp.selectNodes(envelope);

                                Iterator nodesIter = selectedNodes.iterator();

                            while (nodesIter.hasNext())
                            {
                                OMElement e = (OMElement)nodesIter.next();

                                String localName = e.getLocalName();
                                String namespace = e.getNamespace() != null ? e.getNamespace().getNamespaceURI() : null;

                                WSEncryptionPart encryptedElem = new WSEncryptionPart(localName, namespace,
                            "Content", WSConstants.PART_TYPE_ELEMENT);

                                encryptedElem.setXpath(expression);
                                OMAttribute wsuId = e.getAttribute(new QName(WSConstants.WSU_NS, "Id"));

                                if ( wsuId != null ) {
                                    encryptedElem.setEncId(wsuId.getAttributeValue());
                                }

                                encryptedPartsElements.add(encryptedElem);

                            }

                        } catch (JaxenException e) {
                                // This has to be changed to propagate an instance of a RampartException up
                                throw new RuntimeException(e);
                        }
        }


        return encryptedPartsElements;

    }

    public static Vector getPartsAndElements(boolean sign, SOAPEnvelope envelope, boolean includeBody, Vector parts, Vector elements, Set namespaces) {

        Vector found = new Vector();
        Vector result = new Vector();

        // check body
        if(includeBody) {
            if( sign ) {
                result.add(new WSEncryptionPart(addWsuIdToElement(envelope.getBody()),null,WSConstants.PART_TYPE_BODY));
            } else {
                result.add(new WSEncryptionPart(addWsuIdToElement(envelope.getBody()), "Content", WSConstants.PART_TYPE_BODY));
            }
            found.add( envelope.getBody() );
        }

        // Search envelope header for 'parts' from Policy (SignedParts/EncryptedParts)

        SOAPHeader header = envelope.getHeader();

        for(int i=0; i<parts.size(); i++) {
            WSEncryptionPart wsep = (WSEncryptionPart) parts.get( i );
            if( wsep.getName() == null ) {
                // NO name - search by namespace
                ArrayList headerList = header.getHeaderBlocksWithNSURI( wsep.getNamespace() );

                for(int j=0; j<headerList.size(); j++) {
                    SOAPHeaderBlock shb = (SOAPHeaderBlock) headerList.get( j );

                    // find reference in envelope
                    OMElement e = header.getFirstChildWithName( shb.getQName() );

                    if( ! found.contains(  e ) ) {
                        // found new
                        found.add( e );

                        if( sign ) {
                            result.add(new WSEncryptionPart(e.getLocalName(), wsep.getNamespace(), "Content", WSConstants.PART_TYPE_HEADER));
                        } else {

                            WSEncryptionPart encryptedHeader = new WSEncryptionPart(e.getLocalName(), wsep.getNamespace(), "Element", WSConstants.PART_TYPE_HEADER);
                            OMAttribute wsuId = e.getAttribute(new QName(WSConstants.WSU_NS, "Id"));

                            if ( wsuId != null ) {
                                encryptedHeader.setEncId(wsuId.getAttributeValue());
                            }

                            result.add(encryptedHeader);
                        }
                    }
                }
            } else {
                // try to find
                OMElement e = header.getFirstChildWithName( new QName(wsep.getNamespace(), wsep.getName()) );
                if( e != null ) {
                    if( ! found.contains( e ) ) {
                        // found new (reuse wsep)
                        found.add( e );
                        wsep.setType(WSConstants.PART_TYPE_HEADER);
                        OMAttribute wsuId = e.getAttribute(new QName(WSConstants.WSU_NS, "Id"));

                        if ( wsuId != null ) {
                            wsep.setEncId(wsuId.getAttributeValue());
                        }

                        result.add( wsep );
                    }
                }
            }
        }

        // ?? Search for 'Elements' here

        // decide what exactly is going to be used - only the default namespaces, or the list of all declared namespaces in the message !

        Iterator elementsIter = elements.iterator();
        while (elementsIter.hasNext())
        {
        	String expression = (String)elementsIter.next();
        	try {
				XPath xp = new AXIOMXPath(expression);
				Iterator nsIter = namespaces.iterator();

				while (nsIter.hasNext())
				{
					OMNamespace tmpNs = (OMNamespace)nsIter.next();
					xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
				}

				List selectedNodes = xp.selectNodes(envelope);

				Iterator nodesIter = selectedNodes.iterator();
			    while (nodesIter.hasNext())
			    {
			    	OMElement e = (OMElement)nodesIter.next();
			    	String localName = e.getLocalName();
                    String namespace = e.getNamespace() != null ? e.getNamespace().getNamespaceURI() : null;

			    	if (sign) {
                        WSEncryptionPart encryptedElem = new WSEncryptionPart(localName,namespace, "Content", WSConstants.PART_TYPE_ELEMENT);
                        encryptedElem.setXpath(expression);
                        result.add(encryptedElem);

                    } else {

                        WSEncryptionPart encryptedElem = new WSEncryptionPart(localName,namespace, "Element", WSConstants.PART_TYPE_ELEMENT);
                        encryptedElem.setXpath(expression);

			    		OMAttribute wsuId = e.getAttribute(new QName(WSConstants.WSU_NS, "Id"));

			    		if ( wsuId != null ) {
			    		    encryptedElem.setEncId(wsuId.getAttributeValue());
			    		}

			    		result.add(encryptedElem);
			    	}
			    }

			} catch (JaxenException e) {
				// This has to be changed to propagate an instance of a RampartException up
				throw new RuntimeException(e);
			}
        }

        return result;
    }

    /**
     * Get a element for SOAP
     * @param envelope   SOAP Envelope of which we should check required elements
     * @param namespaces  Declared namespaces in RequiredElements assertion
     * @param expression  XPATH expression of required elements
     * @return
     */
    public static boolean checkRequiredElements(SOAPEnvelope envelope, Set namespaces, String expression ) {

        // The XPath expression must be evaluated against the SOAP header
        // http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/ws-securitypolicy-1.2-spec-os.html#_Toc161826519
        SOAPHeader header = envelope.getHeader();

        try {
                        XPath xp = new AXIOMXPath(expression);
                        Iterator nsIter = namespaces.iterator();

                        while (nsIter.hasNext())
                        {
                                OMNamespace tmpNs = (OMNamespace)nsIter.next();
                                xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
                        }

                        List selectedNodes = xp.selectNodes(header);

                        if (selectedNodes.size() == 0 ) {
                            return false;
                        }

        } catch (JaxenException e) {
                // This has to be changed to propagate an instance of a RampartException up
                throw new RuntimeException(e);
        }

        return true;
    }


    public static KeyGenerator getEncryptionKeyGenerator(String symEncrAlgo) throws WSSecurityException {
        KeyGenerator keyGen;
        try {
            /*
             * Assume AES as default, so initialize it
             */
            keyGen = KeyGenerator.getInstance("AES");
            if (symEncrAlgo.equalsIgnoreCase(WSConstants.TRIPLE_DES)) {
                keyGen = KeyGenerator.getInstance("DESede");
            } else if (symEncrAlgo.equalsIgnoreCase(WSConstants.AES_128)) {
                keyGen.init(128);
            } else if (symEncrAlgo.equalsIgnoreCase(WSConstants.AES_192)) {
                keyGen.init(192);
            } else if (symEncrAlgo.equalsIgnoreCase(WSConstants.AES_256)) {
                keyGen.init(256);
            } else {
                return null;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e);
        }
        return keyGen;
    }

    /**
     * Creates the unique (reproducible) id for to hold the context identifier
     * of the message exchange.
     * @return Id to hold the context identifier in the message context
     */
    public static String getContextIdentifierKey(MessageContext msgContext) {
        return msgContext.getAxisService().getName();
    }


    /**
     * Returns the map of security context token identifiers
     * @return the map of security context token identifiers
     */
    public static Hashtable getContextMap(MessageContext msgContext) {
        //Fist check whether its there
        Object map = msgContext.getConfigurationContext().getProperty(
                ConversationConstants.KEY_CONTEXT_MAP);

        if(map == null) {
            //If not create a new one
            map = new Hashtable();
            //Set the map globally
            msgContext.getConfigurationContext().setProperty(
                    ConversationConstants.KEY_CONTEXT_MAP, map);
        }

        return (Hashtable)map;
    }

    public static boolean isTokenValid(RampartMessageData rmd, String id) throws RampartException {
        try {
            org.apache.rahas.Token token = rmd.getTokenStorage().getToken(id);
            return token!= null && token.getState() == org.apache.rahas.Token.ISSUED;
        } catch (TrustException e) {
            throw new RampartException("errorExtractingToken");
        }
    }

    public static void setEncryptionUser(RampartMessageData rmd, WSSecEncryptedKey encrKeyBuilder)
            throws RampartException {
        RampartPolicyData rpd = rmd.getPolicyData();
        String encrUser = rpd.getRampartConfig().getEncryptionUser();
        setEncryptionUser(rmd, encrKeyBuilder, encrUser);
    }

    public static void setEncryptionUser(RampartMessageData rmd, WSSecEncryptedKey encrKeyBuilder,
            String encrUser) throws RampartException {
        RampartPolicyData rpd = rmd.getPolicyData();

        if (encrUser == null) {
            encrUser = rpd.getRampartConfig().getEncryptionUser();
        }

        if (encrUser == null || "".equals(encrUser)) {
            throw new RampartException("missingEncryptionUser");
        }
        if(encrUser.equals(WSHandlerConstants.USE_REQ_SIG_CERT)) {
            Object resultsObj = rmd.getMsgContext().getProperty(WSHandlerConstants.RECV_RESULTS);
            if(resultsObj != null) {
                encrKeyBuilder.setUseThisCert(getReqSigCert((Vector)resultsObj));

                //TODO This is a hack, this should not come under USE_REQ_SIG_CERT
                if(encrKeyBuilder.isCertSet()) {
                	encrKeyBuilder.setUserInfo(getUsername((Vector)resultsObj));
                }


            } else {
                throw new RampartException("noSecurityResults");
            }
        } else {
            encrKeyBuilder.setUserInfo(encrUser);
        }
    }

    /**
     * Sets the keyIdentifierType of <code>WSSecSignature</code> or <code>WSSecEncryptedKey</code>
     * according to the given <code>Token</code> and <code>RampartPolicyData</code>
     * First check the requirements specified under Token Assertion and if not found check
     * the WSS11 and WSS10 assertions
     */

    public static void setKeyIdentifierType(RampartMessageData rmd, WSSecBase secBase,org.apache.ws.secpolicy.model.Token token) {

        // Use a reference rather than the binary security token if: the policy never allows the token to be
        // included; or this is the recipient and the token should only be included in requests; or this is
        // the initiator and the token should only be included in responses.
        final boolean useReference = token.getInclusion() == SPConstants.INCLUDE_TOKEN_NEVER
                                     || !rmd.isInitiator() && token.getInclusion() == SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT
                                     || rmd.isInitiator() && token.getInclusion() == SPConstants.INCLUDE_TOEKN_ALWAYS_TO_INITIATOR;
        if (useReference) {

    		boolean tokenTypeSet = false;

    		if(token instanceof X509Token) {
    			X509Token x509Token = (X509Token)token;

    			if(x509Token.isRequireIssuerSerialReference()) {
    				secBase.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
    				tokenTypeSet = true;
    			} else if (x509Token.isRequireKeyIdentifierReference()) {
    				secBase.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
    				tokenTypeSet = true;
    			} else if (x509Token.isRequireThumbprintReference()) {
    				secBase.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
    				
    				tokenTypeSet = true;
                } else if (x509Token.isRequireEmbeddedTokenReference()) {
                    secBase.setKeyIdentifierType(WSConstants.EMBED_SECURITY_TOKEN_REF);
                    tokenTypeSet = true;
                }
            }

    		if (!tokenTypeSet) {
                final RampartPolicyData rpd = rmd.getPolicyData();
	    		Wss10 wss = rpd.getWss11();
				if (wss == null) {
					wss = rpd.getWss10();
				}

				if (wss.isMustSupportRefKeyIdentifier()) {
					secBase.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
				} else if (wss.isMustSupportRefIssuerSerial()) {
					secBase.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
				} else if (wss instanceof Wss11
						&& ((Wss11) wss).isMustSupportRefThumbprint()) {
					secBase.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
				}
    		}

		} else {
			if (token instanceof IssuedToken) {
				secBase.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
			} else {
				secBase.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
			}
		}
    }

    private static X509Certificate getReqSigCert(Vector results) {
        /*
        * Scan the results for a matching actor. Use results only if the
        * receiving Actor and the sending Actor match.
        */
        for (int i = 0; i < results.size(); i++) {
            WSHandlerResult rResult =
                    (WSHandlerResult) results.get(i);

            Vector wsSecEngineResults = rResult.getResults();
            /*
            * Scan the results for the first Signature action. Use the
            * certificate of this Signature to set the certificate for the
            * encryption action :-).
            */
            for (int j = 0; j < wsSecEngineResults.size(); j++) {
                WSSecurityEngineResult wser =
                        (WSSecurityEngineResult) wsSecEngineResults.get(j);
                Integer actInt = (Integer)wser.get(WSSecurityEngineResult.TAG_ACTION);
                if (actInt.intValue() == WSConstants.SIGN) {
                    return (X509Certificate)wser.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                }
            }
        }

        return null;
    }

    /**
     * Scan through <code>WSHandlerResult<code> vector for a Username token and return
     * the username if a Username Token found
     * @param results
     * @return
     */

    public static String getUsername(Vector results) {
        /*
         * Scan the results for a matching actor. Use results only if the
         * receiving Actor and the sending Actor match.
         */
         for (int i = 0; i < results.size(); i++) {
             WSHandlerResult rResult =
                     (WSHandlerResult) results.get(i);

             Vector wsSecEngineResults = rResult.getResults();
             /*
             * Scan the results for a username token. Use the username
             * of this token to set the alias for the encryption user
             */
             for (int j = 0; j < wsSecEngineResults.size(); j++) {
                 WSSecurityEngineResult wser =
                         (WSSecurityEngineResult) wsSecEngineResults.get(j);
                 Integer actInt = (Integer)wser.get(WSSecurityEngineResult.TAG_ACTION);
                 if (actInt.intValue() == WSConstants.UT) {
                	 WSUsernameTokenPrincipal principal = (WSUsernameTokenPrincipal)wser.get(WSSecurityEngineResult.TAG_PRINCIPAL);
                     return principal.getName();
                 }
             }
         }

         return null;
    }

    public static String getRequestEncryptedKeyId(Vector results) {

        for (int i = 0; i < results.size(); i++) {
            WSHandlerResult rResult =
                    (WSHandlerResult) results.get(i);

            Vector wsSecEngineResults = rResult.getResults();
            /*
            * Scan the results for the first Signature action. Use the
            * certificate of this Signature to set the certificate for the
            * encryption action :-).
            */
            for (int j = 0; j < wsSecEngineResults.size(); j++) {
                WSSecurityEngineResult wser =
                        (WSSecurityEngineResult) wsSecEngineResults.get(j);
                Integer actInt = (Integer)wser.get(WSSecurityEngineResult.TAG_ACTION);
                String encrKeyId = (String)wser.get(WSSecurityEngineResult.TAG_ENCRYPTED_KEY_ID);
                if (actInt.intValue() == WSConstants.ENCR &&
                        encrKeyId != null) {
                    return encrKeyId;
                }
            }
        }

        return null;
    }

    public static byte[] getRequestEncryptedKeyValue(Vector results) {

        for (int i = 0; i < results.size(); i++) {
            WSHandlerResult rResult =
                    (WSHandlerResult) results.get(i);

            Vector wsSecEngineResults = rResult.getResults();
            /*
            * Scan the results for the first Signature action. Use the
            * certificate of this Signature to set the certificate for the
            * encryption action :-).
            */
            for (int j = 0; j < wsSecEngineResults.size(); j++) {
                WSSecurityEngineResult wser =
                        (WSSecurityEngineResult) wsSecEngineResults.get(j);
                Integer actInt = (Integer)wser.get(WSSecurityEngineResult.TAG_ACTION);
                byte[] decryptedKey = (byte[])wser.get(WSSecurityEngineResult.TAG_DECRYPTED_KEY);
                if (actInt.intValue() == WSConstants.ENCR &&
                        decryptedKey != null) {
                    return decryptedKey;
                }
            }
        }

        return null;
    }

    /**
     * If the child is present insert the element as a sibling after him.
     *
     * If the child is null, then prepend the element.
     *
     * @param rmd
     * @param child
     * @param elem - element mentioned above
     * @return
     */
    public static Element insertSiblingAfterOrPrepend(RampartMessageData rmd, Element child, Element elem) {
        Element retElem = null;
    	if(child != null){ // child is not null so insert sibling after
    		retElem = RampartUtil.insertSiblingAfter(rmd, child, elem);
    	}else{ //Prepend
                retElem = prependSecHeader(rmd, elem);
    	}

    	return retElem;
    }

    public static Element insertSiblingBeforeOrPrepend(RampartMessageData rmd, Element child, Element elem) {
        Element retElem = null;
        if(child != null && child.getPreviousSibling() != null){
                retElem = RampartUtil.insertSiblingBefore(rmd, child, elem);
        }else{ //Prepend
                retElem = prependSecHeader(rmd, elem);
        }

        return retElem;
    }

    private static Element prependSecHeader(RampartMessageData rmd, Element elem){
        Element retElem = null;

        Element secHeaderElem = rmd.getSecHeader().getSecurityHeader();
        Node node = secHeaderElem.getOwnerDocument().importNode(
                elem, true);
        Element firstElem = (Element)secHeaderElem.getFirstChild();

        if(firstElem == null){
                retElem = (Element)secHeaderElem.appendChild(node);
        }else{
                if(firstElem.getOwnerDocument().equals(elem.getOwnerDocument())) {
                        ((OMElement)firstElem).insertSiblingBefore((OMElement)elem);
                retElem = elem;
                } else {
                        Element newSib = (Element)firstElem.getOwnerDocument().importNode(elem, true);
                        ((OMElement)firstElem).insertSiblingBefore((OMElement)newSib);
                        retElem = newSib;
                }
        }

        return retElem;
    }

    /**
     * Method to check whether security header is required in incoming message
     * @param rpd
     * @return true if a security header is required in the incoming message
     */
    public static boolean isSecHeaderRequired(RampartPolicyData rpd, boolean initiator,
                                                                                boolean inflow ) {

        // Checking for time stamp
        if ( rpd.isIncludeTimestamp() ) {
            return true;
        }

        // Checking for signed parts and elements
        if (rpd.isSignBody() || rpd.getSignedParts().size() != 0 ||
                                    rpd.getSignedElements().size() != 0) {
            return true;
        }

        // Checking for encrypted parts and elements
        if (rpd.isEncryptBody() || rpd.getEncryptedParts().size() != 0 ||
                                    rpd.getEncryptedElements().size() != 0 ) {
            return true;
        }

        // Checking for supporting tokens
        SupportingToken supportingTokens;

        if (!initiator && inflow || initiator && !inflow ) {

            Vector supportingToks = rpd.getSupportingTokensList();
            for (int i = 0; i < supportingToks.size(); i++) {
                supportingTokens = (SupportingToken) supportingToks.get(i);
                if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                    return true;
                }
            }

            supportingTokens = rpd.getSignedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }

            supportingTokens = rpd.getEndorsingSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }

            supportingTokens = rpd.getSignedEndorsingSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }

            supportingTokens = rpd.getEncryptedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }

            supportingTokens = rpd.getSignedEncryptedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }

            supportingTokens = rpd.getEndorsingEncryptedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }

            supportingTokens = rpd.getSignedEndorsingEncryptedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }
        }

        return false;

    }

    public static void handleEncryptedSignedHeaders(Vector encryptedParts, Vector signedParts, Document doc) {

        //TODO Is there a more efficient  way to do this ? better search algorithm 
        for (int i = 0 ; i < signedParts.size() ; i++) {
            WSEncryptionPart signedPart = (WSEncryptionPart)signedParts.get(i);

            //This signed part is not a header
            if (signedPart.getNamespace() == null || signedPart.getName() == null) {
                continue;
            }

            for (int j = 0 ; j < encryptedParts.size() ; j ++) {
                WSEncryptionPart encryptedPart = (WSEncryptionPart) encryptedParts.get(j);

                if (encryptedPart.getNamespace() == null || encryptedPart.getName() == null ) {
                    continue;
                }

                if (signedPart.getName().equals(encryptedPart.getName()) &&
                        signedPart.getNamespace().equals(encryptedPart.getNamespace())) {

                    String encDataID =  encryptedPart.getEncId();
                    Element encDataElem = WSSecurityUtil.findElementById(doc.getDocumentElement(), encDataID, null);

                    if (encDataElem != null) {
                        Element encHeader = (Element)encDataElem.getParentNode();
                        String encHeaderId = encHeader.getAttributeNS(WSConstants.WSU_NS, "Id");

                        //For some reason the id might not be available
                        // so the part/element with empty/null id won't be recognized afterwards. 
                        if (encHeaderId != null && !"".equals(encHeaderId.trim())) {
                            signedParts.remove(signedPart);
                            WSEncryptionPart encHeaderToSign = new WSEncryptionPart(encHeaderId);
                            signedParts.add(encHeaderToSign);
                        }

                    }
                }
            }


        }

    }

    public static String getSigElementId(RampartMessageData rmd) {

        SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();

        SOAPHeader header = envelope.getHeader();

        if (header == null ) {
            return null;
        }

        ArrayList secHeaders = header.getHeaderBlocksWithNSURI(WSConstants.WSSE_NS);

        if (secHeaders != null && secHeaders.size() > 0) {
            QName sigQName = new QName(Constants.SignatureSpecNS,Constants._TAG_SIGNATURE);
            QName wsuIdQName = new QName(WSConstants.WSU_NS,"Id");
            OMElement sigElem = ((SOAPHeaderBlock)secHeaders.get(0)).getFirstChildWithName(sigQName);
            OMAttribute wsuId = sigElem.getAttribute(wsuIdQName);

            if (wsuId != null) {
                return wsuId.getAttributeValue();
            }

            wsuId = sigElem.getAttribute(new QName("Id"));

            if (wsuId != null) {
                return wsuId.getAttributeValue();
            }


        }

        return null;
    }

    /**
     * We use this method to prevent the singleton behavior of WSSConfig
     * @return WSSConfig object with the latest settings.
     */

    public static WSSConfig getWSSConfigInstance() {

        WSSConfig defaultWssConfig = WSSConfig.getDefaultWSConfig();
        WSSConfig wssConfig = WSSConfig.getNewInstance();

        wssConfig.setEnableSignatureConfirmation(defaultWssConfig.isEnableSignatureConfirmation());
        wssConfig.setTimeStampStrict(defaultWssConfig.isTimeStampStrict());
        wssConfig.setWsiBSPCompliant(defaultWssConfig.isWsiBSPCompliant());
        wssConfig.setPrecisionInMilliSeconds(defaultWssConfig.isPrecisionInMilliSeconds());

        return  wssConfig;

    }

    public static void validateTransport(RampartMessageData rmd) throws RampartException {

        RampartPolicyData rpd = rmd.getPolicyData();

        if (rpd == null) {
            return;
        }

        if (rpd.isTransportBinding() && !rmd.isInitiator()) {
            if (rpd.getTransportToken() instanceof HttpsToken) {
                String incomingTransport = rmd.getMsgContext().getIncomingTransportName();
                if (!incomingTransport.equals(org.apache.axis2.Constants.TRANSPORT_HTTPS)) {
                    throw new RampartException("invalidTransport",
                            new String[]{incomingTransport});
                }
                if (((HttpsToken) rpd.getTransportToken()).isRequireClientCertificate()) {
                    MessageContext messageContext = rmd.getMsgContext();
                    if(messageContext.getProperty("ssl.client.auth.cert.X509") == null){
                        HttpServletRequest request = ((HttpServletRequest) messageContext.
                                                getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST));
                        if (request == null ||
                                request.getAttribute("javax.servlet.request.X509Certificate") == null) {
                            throw new RampartException("clientAuthRequired");
                        }
                    }
                }
            }
        }
    }

    private static Crypto retrieveCryptoFromCache(String cryptoKey, String refreshInterval) {
        // cache hit
        if (cryptoStore.containsKey(cryptoKey)) {
            CachedCrypto cachedCrypto = cryptoStore.get(cryptoKey);
            if (refreshInterval != null) {
                if (cachedCrypto.creationTime + new Long(refreshInterval).longValue() > Calendar
                        .getInstance().getTimeInMillis()) {
                    log.debug("Cache Hit : Crypto Object was found in cache.");
                    return cachedCrypto.crypto;
                } else {
                    log.debug("Cache Miss : Crypto Object found in cache is expired.");
                    return null;
                }
            } else {
                log.debug("Cache Hit : Crypto Object was found in cache.");
                return cachedCrypto.crypto;
            }
        }
        // cache miss
        else {
            log.debug("Cache Miss : Crypto Object was not found in cache.");
            return null;
        }
    }

    private static void cacheCrypto(String cryptoKey, Crypto crypto) {
        cryptoStore.put(cryptoKey, new CachedCrypto(crypto, Calendar.getInstance()
                .getTimeInMillis()));
        log.debug("Crypto object is inserted into the Cache.");

    }


}
