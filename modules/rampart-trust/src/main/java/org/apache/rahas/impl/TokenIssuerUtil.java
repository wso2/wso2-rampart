/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.rahas.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.Base64;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.Rahas;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.STSConstants;
import org.apache.rahas.Token;
import org.apache.rahas.TokenPersister;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.dkalgo.P_SHA1;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.dao.ApplicationDAO;
import org.wso2.carbon.identity.application.mgt.dao.impl.ApplicationDAOImpl;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 */
public class TokenIssuerUtil {

    private static final Log log = LogFactory.getLog(TokenIssuerUtil.class);

    public final static String ENCRYPTED_KEY = "EncryptedKey";
    public final static String BINARY_SECRET = "BinarySecret";

    public static byte[] getSharedSecret(RahasData data,
                                         int keyComputation,
                                         int keySize) throws TrustException {

        boolean reqEntrPresent = data.getRequestEntropy() != null;

        try {
            if (reqEntrPresent &&
                keyComputation != SAMLTokenIssuerConfig.KeyComputation.KEY_COMP_USE_OWN_KEY) {
                //If there is requester entropy and if the issuer is not
                //configured to use its own key

                if (keyComputation ==
                    SAMLTokenIssuerConfig.KeyComputation.KEY_COMP_PROVIDE_ENT) {
                    data.setResponseEntropy(WSSecurityUtil.generateNonce(keySize / 8));
                    P_SHA1 p_sha1 = new P_SHA1();
                    return p_sha1.createKey(data.getRequestEntropy(),
                                            data.getResponseEntropy(),
                                            0,
                                            keySize / 8);
                } else {
                    //If we reach this its expected to use the requestor's
                    //entropy
                    return data.getRequestEntropy();
                }
            } else { // need to use a generated key
                return generateEphemeralKey(keySize);
            }
        } catch (WSSecurityException e) {
            throw new TrustException("errorCreatingSymmKey", e);
        } catch (ConversationException e) {
            throw new TrustException("errorCreatingSymmKey", e);
        }
    }

    public static void handleRequestedProofToken(RahasData data,
                                                 int wstVersion,
                                                 AbstractIssuerConfig config,
                                                 OMElement rstrElem,
                                                 Token token,
                                                 Document doc) throws TrustException {
        OMElement reqProofTokElem =
                TrustUtil.createRequestedProofTokenElement(wstVersion, rstrElem);

        if (config.keyComputation == AbstractIssuerConfig.KeyComputation.KEY_COMP_PROVIDE_ENT
            && data.getRequestEntropy() != null) {
            //If we there's requester entropy and its configured to provide
            //entropy then we have to set the entropy value and
            //set the RPT to include a ComputedKey element

            OMElement respEntrElem = TrustUtil.createEntropyElement(wstVersion, rstrElem);
            String entr = Base64.encode(data.getResponseEntropy());
            OMElement binSecElem = TrustUtil.createBinarySecretElement(wstVersion,
                                                            respEntrElem,
                                                            RahasConstants.BIN_SEC_TYPE_NONCE);
            binSecElem.setText(entr);

            OMElement compKeyElem =
                    TrustUtil.createComputedKeyElement(wstVersion, reqProofTokElem);
            compKeyElem.setText(data.getWstNs() + RahasConstants.COMPUTED_KEY_PSHA1);
        } else {
            if (TokenIssuerUtil.ENCRYPTED_KEY.equals(config.proofKeyType)) {
                WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
                Crypto crypto;
                if (config.cryptoElement != null) { // crypto props defined as elements
                    crypto = CryptoFactory.getInstance(TrustUtil.toProperties(config.cryptoElement),
                                                       data.getInMessageContext().
                                                               getAxisService().getClassLoader());
                } else { // crypto props defined in a properties file
                    crypto = CryptoFactory.getInstance(config.cryptoPropertiesFile,
                                                       data.getInMessageContext().
                                                               getAxisService().getClassLoader());
                }

                encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
                try {
                    encrKeyBuilder.setUseThisCert(data.getClientCert());
                    encrKeyBuilder.prepare(doc, crypto);
                } catch (WSSecurityException e) {
                    throw new TrustException("errorInBuildingTheEncryptedKeyForPrincipal",
                                             new String[]{data.
                                                     getClientCert().getSubjectDN().getName()});
                }
                Element encryptedKeyElem = encrKeyBuilder.getEncryptedKeyElement();
                Element bstElem = encrKeyBuilder.getBinarySecurityTokenElement();
                if (bstElem != null) {
                    reqProofTokElem.addChild((OMElement) bstElem);
                }

                reqProofTokElem.addChild((OMElement) encryptedKeyElem);

                token.setSecret(encrKeyBuilder.getEphemeralKey());
            } else if (TokenIssuerUtil.BINARY_SECRET.equals(config.proofKeyType)) {
                byte[] secret = TokenIssuerUtil.getSharedSecret(data,
                                                                config.keyComputation,
                                                                config.keySize);
                OMElement binSecElem = TrustUtil.createBinarySecretElement(wstVersion,
                                                                           reqProofTokElem,
                                                                           null);

                binSecElem.setText(Base64.encode(token.getSecret()));
            } else {
                throw new IllegalArgumentException(config.proofKeyType);
            }
        }
    }

    private static byte[] generateEphemeralKey(int keySize) throws TrustException {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] temp = new byte[keySize / 8];
            random.nextBytes(temp);
            return temp;
        } catch (Exception e) {
            throw new TrustException("errorCreatingSymmKey", e);
        }
    }

    /**
     * Util method that checks whether a persister is configured. 
     * @param samlIssuerConfig
     * @return
     */
    public static boolean isPersisterConfigured(AbstractIssuerConfig samlIssuerConfig) {
        return ((SAMLTokenIssuerConfig) samlIssuerConfig).getPersisterClassName() != null;
    }

    /**
     * Set the issuer config in config ctx to be referenced in a later stage of the flow.
     * @param samlIssuerConfig
     * @param msgCxt
     */
    public static void setIssuerConfigInConfigCtx(AbstractIssuerConfig samlIssuerConfig,
                                                  MessageContext msgCxt) {
        msgCxt.getConfigurationContext().setProperty(STSConstants.KEY_ISSUER_CONFIG,
                                                     samlIssuerConfig);
    }

    /**
     * Reads the TokenPersister configuration from TokenIssuerConfig and create TokenPersister.
     *
     * @param config
     */
    public static TokenPersister getTokenPersister(AbstractIssuerConfig config,
                                                   MessageContext inMsgCtx) throws TrustException {
        //create token persister and set it in configuration context
        TokenPersister tokenPersister = null;
        if (((SAMLTokenIssuerConfig) config).getPersisterClassName() != null) {
            String persisterClassName = ((SAMLTokenIssuerConfig) config).getPersisterClassName();
            try {
                Class persisterCalss = Loader.loadClass(inMsgCtx.getAxisService().getClassLoader(), persisterClassName);
                tokenPersister = (TokenPersister) persisterCalss.newInstance();
                //initialize config properties.
                tokenPersister.setConfiguration(config);
                //set message context
                tokenPersister.setMessageContext(inMsgCtx);
            } catch (ClassNotFoundException e) {
                String errorMsg = "Can not load the class" + persisterClassName;
                throw new TrustException(errorMsg, e);
            } catch (InstantiationException e) {
                String errorMessage = "Can not create token persister instance.";
                throw new TrustException(errorMessage, e);
            } catch (IllegalAccessException e) {
                String errorMessage = "Can not create token persister instance.";
                throw new TrustException(errorMessage, e);
            }
        }
        return tokenPersister;
    }

    /**
     * This initializes token persister and related config and set them in config context if they
     * are not already set.
     *
     * @param config
     * @param inMsgCtx
     * @throws TrustException
     */
    public static void manageTokenPersistenceSettings(AbstractIssuerConfig config,
                                                      MessageContext inMsgCtx)
            throws TrustException {

        try {
            //get config context
            ConfigurationContext configCtx = inMsgCtx.getConfigurationContext();
            //add persister if not already exist
            if (configCtx.getProperty(TokenPersister.TOKEN_PERSISTER_KEY) == null) {
                synchronized (TokenIssuerUtil.class) {
                    if (configCtx.getProperty(TokenPersister.TOKEN_PERSISTER_KEY) == null) {
                        TokenPersister tokenPersister = getTokenPersister(config, inMsgCtx);
                        if (tokenPersister != null) {
                                configCtx.setProperty(TokenPersister.TOKEN_PERSISTER_KEY, tokenPersister);
                                if (configCtx.getProperty(TokenStorage.TOKEN_STORAGE_KEY) != null) {
                                    //set persister and storage in Rahas module class to be used for persistence on shutdown.
                                    Rahas.setPersistanceStorage(tokenPersister, (TokenStorage) configCtx.getProperty(
                                            TokenStorage.TOKEN_STORAGE_KEY));
                                }
                                //set axis2 observer
                            }
                    }
                }
            }
            /*set SAMLTokenIssuerConfig in configuration context for reading persister info later.
            *hence it should be set only once.*/
            if (configCtx.getProperty(STSConstants.KEY_ISSUER_CONFIG) == null) {
                synchronized (TokenIssuerUtil.class) {
                    if(configCtx.getProperty(STSConstants.KEY_ISSUER_CONFIG) == null){
                        setIssuerConfigInConfigCtx(config, inMsgCtx);
                    }
                }
            }
        } catch (TrustException e) {
            throw new TrustException("Error in initializing persister settings.", e);
        }
    }

    public static List<String> getAdditionalSAMLAudiencesFromAssociatedServiceProvider(String issuerAddress) {

        List<String> additionalAudiences = new ArrayList<String>(0);

        if (StringUtils.isNotBlank(issuerAddress)) {
            try {
                ApplicationDAO applicationDAO = new ApplicationDAOImpl();
                String existingSPName = applicationDAO.getServiceProviderNameByClientId
                        (issuerAddress, "wstrust", CarbonContext
                                .getThreadLocalCarbonContext().getTenantDomain());
                if (StringUtils.isNotBlank(existingSPName)) {
                    ServiceProvider serviceProvider = applicationDAO.getApplication(existingSPName, CarbonContext
                            .getThreadLocalCarbonContext().getTenantDomain());
                    InboundAuthenticationRequestConfig[] inboundAuthReqConfigs = serviceProvider
                            .getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
                    for (InboundAuthenticationRequestConfig entry : inboundAuthReqConfigs)
                        if ("wstrust".equalsIgnoreCase(entry.getInboundAuthType())
                                && !issuerAddress.equalsIgnoreCase(entry.getInboundAuthKey()))
                            additionalAudiences.add(entry.getInboundAuthKey());
                }
            } catch (IdentityApplicationManagementException e) {
                if (log.isDebugEnabled())
                    log.debug("Couldn't match trusted service: <wstrust:"+issuerAddress+"> to an active Service Provider");
            }
        }

        return additionalAudiences;
    }

}
