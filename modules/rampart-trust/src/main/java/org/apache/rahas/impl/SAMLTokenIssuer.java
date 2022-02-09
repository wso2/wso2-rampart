///*
// * Copyright 2004,2005 The Apache Software Foundation.
// *
// * Licensed under the Apache License, Version 2.0 (the "License");
// * you may not use this file except in compliance with the License.
// * You may obtain a copy of the License at
// *
// *      http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// * See the License for the specific language governing permissions and
// * limitations under the License.
// */
//
//package org.apache.rahas.impl;
//
//import org.apache.axiom.om.OMElement;
//import org.apache.axiom.om.OMFactory;
//import org.apache.axiom.om.OMNode;
//import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
//import org.apache.axiom.soap.SOAPEnvelope;
//import org.apache.axis2.context.MessageContext;
//import org.apache.axis2.description.Parameter;
//import org.apache.commons.lang.ArrayUtils;
//import org.apache.commons.lang.StringUtils;
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//import org.apache.rahas.RahasConstants;
//import org.apache.rahas.RahasData;
//import org.apache.rahas.Token;
//import org.apache.rahas.TokenIssuer;
//import org.apache.rahas.TrustException;
//import org.apache.rahas.TrustUtil;
//import org.apache.rahas.impl.util.SAMLAttributeCallback;
//import org.apache.rahas.impl.util.SAMLCallbackHandler;
//import org.apache.rahas.impl.util.SAMLNameIdentifierCallback;
//import org.apache.rahas.impl.util.SAMLUtils;
//import org.apache.ws.security.KerberosTokenPrincipal;
//import org.apache.ws.security.WSConstants;
//import org.apache.ws.security.WSSecurityException;
//import org.apache.ws.security.WSUsernameTokenPrincipal;
//import org.apache.ws.security.components.crypto.Crypto;
//import org.apache.ws.security.components.crypto.CryptoFactory;
//import org.apache.ws.security.message.WSSecEncryptedKey;
//import org.apache.ws.security.message.token.SecurityTokenReference;
//import org.apache.ws.security.util.Base64;
//import org.apache.ws.security.util.Loader;
//import org.apache.ws.security.util.XmlSchemaDateFormat;
//import org.apache.xml.security.signature.XMLSignature;
//import org.apache.xml.security.utils.EncryptionConstants;
//import org.opensaml.SAMLAssertion;
//import org.opensaml.SAMLAttribute;
//import org.opensaml.SAMLAttributeStatement;
//import org.opensaml.SAMLAudienceRestrictionCondition;
//import org.opensaml.SAMLAuthenticationStatement;
//import org.opensaml.SAMLCondition;
//import org.opensaml.SAMLException;
//import org.opensaml.SAMLNameIdentifier;
//import org.opensaml.SAMLStatement;
//import org.opensaml.SAMLSubject;
//import org.opensaml.saml2.core.Audience;
//import org.opensaml.saml2.core.AudienceRestriction;
//import org.opensaml.saml2.core.impl.AudienceBuilder;
//import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
//import org.w3c.dom.Document;
//import org.w3c.dom.Element;
//import org.w3c.dom.Node;
//import org.w3c.dom.Text;
//
//import javax.xml.namespace.QName;
//import java.security.Principal;
//import java.security.SecureRandom;
//import java.security.cert.X509Certificate;
//import java.text.DateFormat;
//import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.Date;
//import java.util.List;
//
///**
// * Issuer to issue SAMl tokens
// */
//public class SAMLTokenIssuer implements TokenIssuer {
//
//    protected String configParamName;
//
//    protected OMElement configElement;
//
//    protected String configFile;
//
//    protected String audienceRestriction = null;
//
//    private static final Log log = LogFactory.getLog(SAMLTokenIssuer.class);
//
//    public SOAPEnvelope issue(RahasData data) throws TrustException {
//
//        try {
//            MessageContext inMsgCtx = data.getInMessageContext();
//
//            SAMLTokenIssuerConfig config = null;
//            if (this.configElement != null) {
//                config = new SAMLTokenIssuerConfig(configElement
//                                .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
//            }
//
//            // Look for the file
//            if (config == null && this.configFile != null) {
//                config = new SAMLTokenIssuerConfig(this.configFile);
//            }
//
//            // Look for the param
//            if (config == null && this.configParamName != null) {
//                Parameter param = inMsgCtx.getParameter(this.configParamName);
//                if (param != null && param.getParameterElement() != null) {
//                    config = new SAMLTokenIssuerConfig(param
//                            .getParameterElement().getFirstChildWithName(
//                                    SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
//                } else {
//                    throw new TrustException("expectedParameterMissing",
//                            new String[] { this.configParamName });
//                }
//            }
//
//            if (config == null) {
//                throw new TrustException("configurationIsNull");
//            }
//
//            //initialize and set token persister and config in configuration context.
//            if(TokenIssuerUtil.isPersisterConfigured(config)){
//                TokenIssuerUtil.manageTokenPersistenceSettings(config, inMsgCtx);
//            }
//
//            // if we are adding a doom document builder factory parser pool we don't need to explicitly do this
//            if (!TrustUtil.isDoomParserPoolUsed()) {
//                // Set the DOM impl to DOOM
//                DocumentBuilderFactoryImpl.setDOOMRequired(true);
//            }
//
//            SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx
//                    .getEnvelope().getNamespace().getNamespaceURI());
//
//            Crypto crypto;
//            if (config.cryptoElement != null) { // crypto props
//                                                            // defined as
//                                                            // elements
//                crypto = CryptoFactory.getInstance(TrustUtil
//                        .toProperties(config.cryptoElement), inMsgCtx
//                        .getAxisService().getClassLoader());
//            } else { // crypto props defined in a properties file
//                crypto = CryptoFactory.getInstance(config.cryptoPropertiesFile,
//                        inMsgCtx.getAxisService().getClassLoader());
//            }
//
//
//            if (StringUtils.isBlank(data.getAppliesToAddress())) {
//                audienceRestriction = "defaultAudienceRestriction";
//            }
//
//            audienceRestriction = data.getAppliesToAddress();
//
//
//            // Creation and expiration times
//            Date creationTime = new Date();
//            Date expirationTime = new Date();
//            expirationTime.setTime(creationTime.getTime() + config.ttl);
//
//            // Get the document
//            Document doc = ((Element) env).getOwnerDocument();
//
//            // Get the key size and create a new byte array of that size
//            int keySize = data.getKeysize();
//
//            keySize = (keySize == -1) ? config.keySize : keySize;
//
//            /*
//             * Find the KeyType If the KeyType is SymmetricKey or PublicKey,
//             * issue a SAML HoK assertion. - In the case of the PublicKey, in
//             * coming security header MUST contain a certificate (maybe via
//             * signature)
//             *
//             * If the KeyType is Bearer then issue a Bearer assertion
//             *
//             * If the key type is missing we will issue a HoK assertion
//             */
//
//            String keyType = data.getKeyType();
//            SAMLAssertion assertion;
//            if (StringUtils.isBlank(keyType)) {
//                //According to ws-trust-1.3; <keytype> is an optional URI element.
//                if (StringUtils.isNotBlank(data.getAppliesToAddress())) {
//                    keyType = data.getRstElement().getNamespace().getNamespaceURI() + RahasConstants.KEY_TYPE_SYMM_KEY;
//
//                } else {
//                    throw new TrustException(TrustException.INVALID_REQUEST,
//                            new String[]{"Requested KeyType is missing"});
//                }
//            }
//
//            if (keyType.endsWith(RahasConstants.KEY_TYPE_SYMM_KEY)
//                    || keyType.endsWith(RahasConstants.KEY_TYPE_PUBLIC_KEY)) {
//                assertion = createHoKAssertion(config, doc, crypto,
//                        creationTime, expirationTime, data);
//            } else if (keyType.endsWith(RahasConstants.KEY_TYPE_BEARER)) {
//                assertion = createBearerAssertion(config, doc, crypto,
//                        creationTime, expirationTime, data);
//            } else {
//                assertion = createBearerAssertion(config, doc, crypto,
//                        creationTime, expirationTime, data);
//            }
//
//            OMElement rstrElem;
//            int wstVersion = data.getVersion();
//            if (RahasConstants.VERSION_05_02 == wstVersion) {
//                rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
//                        wstVersion, env.getBody());
//            } else {
//                OMElement rstrcElem = TrustUtil
//                        .createRequestSecurityTokenResponseCollectionElement(
//                                wstVersion, env.getBody());
//                rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
//                        wstVersion, rstrcElem);
//            }
//
//            TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
//                    RahasConstants.TOK_TYPE_SAML_10);
//
//            if (keyType.endsWith(RahasConstants.KEY_TYPE_SYMM_KEY)) {
//                TrustUtil.createKeySizeElement(wstVersion, rstrElem, keySize);
//            }
//
//            if (config.addRequestedAttachedRef) {
//                createAttachedRef(rstrElem, assertion.getId(),wstVersion);
//                /*
//                 * TrustUtil.createRequestedAttachedRef(wstVersion, rstrElem, "#" +
//                 * assertion.getId(), WSConstants.WSS_SAML_KI_VALUE_TYPE);
//                 */
//            }
//
//            if (config.addRequestedUnattachedRef) {
//                createUnattachedRef(rstrElem, assertion.getId(),wstVersion);
//                /*
//                 * TrustUtil.createRequestedUnattachedRef(wstVersion, rstrElem, assertion.getId(),
//                 * WSConstants.WSS_SAML_KI_VALUE_TYPE);
//                 */
//            }
//
//            if (data.getAppliesToAddress() != null) {
//                TrustUtil.createAppliesToElement(rstrElem, data
//                        .getAppliesToAddress(), data.getAddressingNs());
//            }
//
//            // Use GMT time in milliseconds
//            DateFormat zulu = new XmlSchemaDateFormat();
//
//            // Add the Lifetime element
//            TrustUtil.createLifetimeElement(wstVersion, rstrElem, zulu
//                    .format(creationTime), zulu.format(expirationTime));
//
//            // Create the RequestedSecurityToken element and add the SAML token
//            // to it
//            OMElement reqSecTokenElem = TrustUtil
//                    .createRequestedSecurityTokenElement(wstVersion, rstrElem);
//            Token assertionToken;
//            try {
//                Node tempNode = assertion.toDOM();
//                reqSecTokenElem.addChild((OMNode) ((Element) rstrElem)
//                        .getOwnerDocument().importNode(tempNode, true));
//
//                // Store the token
//                assertionToken = new Token(assertion.getId(),
//                        (OMElement) assertion.toDOM(), creationTime,
//                        expirationTime);
//
//                // At this point we definitely have the secret
//                // Otherwise it should fail with an exception earlier
//                assertionToken.setSecret(data.getEphmeralKey());
//
//            } catch (SAMLException e) {
//                throw new TrustException("samlConverstionError", e);
//            }
//
//            if (keyType.endsWith(RahasConstants.KEY_TYPE_SYMM_KEY)
//                    && config.keyComputation != SAMLTokenIssuerConfig.KeyComputation.KEY_COMP_USE_REQ_ENT) {
//
//                // Add the RequestedProofToken
//                TokenIssuerUtil.handleRequestedProofToken(data, wstVersion,
//                        config, rstrElem, assertionToken, doc);
//            }
//
//			if (!config.isTokenStoreDisabled()) {
//				assertionToken.setPersistenceEnabled(true);
//				TrustUtil.getTokenStore(inMsgCtx).add(assertionToken);
//			}
//
//            return env;
//        } finally {
//            if (!TrustUtil.isDoomParserPoolUsed()) {
//                // Unset the DOM impl to default
//                DocumentBuilderFactoryImpl.setDOOMRequired(false);
//            }
//        }
//
//    }
//
//    /**
//     * Create and add wst:AttachedReference element
//     *
//     * @param rstrElem wst:RequestSecurityToken element
//     * @param id Token identifier
//     * @throws TrustException
//     */
//    protected void createAttachedRef(OMElement rstrElem, String id,int version) throws TrustException {
//        OMFactory fac = null;
//        OMElement rar = null;
//        OMElement str = null;
//        OMElement ki = null;
//
//        String ns = TrustUtil.getWSTNamespace(version);
//        fac = rstrElem.getOMFactory();
//        rar = fac.createOMElement(new QName(ns,
//                RahasConstants.IssuanceBindingLocalNames.REQUESTED_ATTACHED_REFERENCE,
//                RahasConstants.WST_PREFIX), rstrElem);
//        str = fac.createOMElement(new QName(WSConstants.WSSE_NS,
//                SecurityTokenReference.SECURITY_TOKEN_REFERENCE, WSConstants.WSSE_PREFIX), rar);
//        ki = fac.createOMElement(new QName(WSConstants.WSSE_NS, "KeyIdentifier",
//                WSConstants.WSSE_PREFIX), str);
//        ki.addAttribute("ValueType", WSConstants.WSS_SAML_KI_VALUE_TYPE, null);
//        ki.setText(id);
//    }
//
//    /**
//     * Create and add wst:UnattachedReference element
//     *
//     * @param rstrElem wst:RequestSecurityToken element
//     * @param id Token identifier
//     * @throws TrustException
//     */
//    protected void createUnattachedRef(OMElement rstrElem, String id,int version) throws TrustException {
//        OMFactory fac = null;
//        OMElement rar = null;
//        OMElement str = null;
//        OMElement ki = null;
//
//        String ns = TrustUtil.getWSTNamespace(version);
//        fac = rstrElem.getOMFactory();
//        rar = fac.createOMElement(new QName(ns,
//                RahasConstants.IssuanceBindingLocalNames.REQUESTED_UNATTACHED_REFERENCE,
//                RahasConstants.WST_PREFIX), rstrElem);
//        str = fac.createOMElement(new QName(WSConstants.WSSE_NS,
//                SecurityTokenReference.SECURITY_TOKEN_REFERENCE, WSConstants.WSSE_PREFIX), rar);
//        ki = fac.createOMElement(new QName(WSConstants.WSSE_NS, "KeyIdentifier",
//                WSConstants.WSSE_PREFIX), str);
//
//        ki.addAttribute("ValueType", WSConstants.WSS_SAML_KI_VALUE_TYPE, null);
//        ki.setText(id);
//    }
//
//    protected SAMLAssertion createBearerAssertion(SAMLTokenIssuerConfig config,
//                                                  Document doc, Crypto crypto, Date creationTime,
//                                                  Date expirationTime, RahasData data) throws TrustException {
//        try {
//            Principal principal = data.getPrincipal();
//            SAMLAssertion assertion;
//            // In the case where the principal is a UT
//            if (principal instanceof WSUsernameTokenPrincipal
//                    || principal instanceof KerberosTokenPrincipal) {
//                SAMLNameIdentifier nameId = null;
//                if (config.getCallbackHandler() != null) {
//                    SAMLNameIdentifierCallback cb = new SAMLNameIdentifierCallback(data);
//                    cb.setUserId(principal.getName());
//                    SAMLCallbackHandler callbackHandler = config.getCallbackHandler();
//                    callbackHandler.handle(cb);
//                    nameId = cb.getNameId();
//                } else {
//                    nameId = new SAMLNameIdentifier(
//                            principal.getName(), null, SAMLNameIdentifier.FORMAT_EMAIL);
//
//                }
//
//                return createAuthAssertion(doc, SAMLSubject.CONF_BEARER,
//                        nameId, null, config, crypto, creationTime,
//                        expirationTime, data);
//            } else {
//                throw new TrustException("samlUnsupportedPrincipal",
//                        new String[]{principal.getClass().getName()});
//            }
//        } catch (SAMLException e) {
//            throw new TrustException("samlAssertionCreationError", e);
//        }
//    }
//
//    protected SAMLAssertion createHoKAssertion(SAMLTokenIssuerConfig config,
//            Document doc, Crypto crypto, Date creationTime,
//            Date expirationTime, RahasData data) throws TrustException {
//
//        String keyType = data.getKeyType();
//        if (StringUtils.isBlank(keyType)) {
//            keyType = data.getRstElement().getNamespace().getNamespaceURI() + RahasConstants.KEY_TYPE_SYMM_KEY;
//        }
//
//        if (keyType.endsWith(RahasConstants.KEY_TYPE_SYMM_KEY)) {
//            Element encryptedKeyElem;
//            SAMLNameIdentifier nameId = null;
//            X509Certificate serviceCert = null;
//            try {
//                if (data.getPrincipal() != null) {
//                    String subjectNameId = data.getPrincipal().getName();
//                    nameId = new SAMLNameIdentifier(subjectNameId, null, SAMLNameIdentifier.FORMAT_EMAIL);
//                }
//
//                // Get ApliesTo to figure out which service to issue the token
//                // for
//                serviceCert = getServiceCert(config, crypto, data
//                        .getAppliesToAddress());
//
//                // Create the encrypted key
//                WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
//
//                // Use thumbprint id
//                encrKeyBuilder
//                        .setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
//
//                // SEt the encryption cert
//                encrKeyBuilder.setUseThisCert(serviceCert);
//
//                // set keysize
//                int keysize = data.getKeysize();
//                keysize = (keysize != -1) ? keysize : config.keySize;
//                encrKeyBuilder.setKeySize(keysize);
//
//                encrKeyBuilder.setEphemeralKey(TokenIssuerUtil.getSharedSecret(
//                        data, config.keyComputation, keysize));
//
//                // Set key encryption algo
//                encrKeyBuilder
//                        .setKeyEncAlgo(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
//
//                // Build
//                encrKeyBuilder.prepare(doc, crypto);
//
//                // Extract the base64 encoded secret value
//                byte[] tempKey = new byte[keysize / 8];
//                System.arraycopy(encrKeyBuilder.getEphemeralKey(), 0, tempKey,
//                        0, keysize / 8);
//
//                data.setEphmeralKey(tempKey);
//
//                // Extract the Encryptedkey DOM element
//                encryptedKeyElem = encrKeyBuilder.getEncryptedKeyElement();
//            } catch (Exception e) {
//                throw new TrustException(
//                        "errorInBuildingTheEncryptedKeyForPrincipal",
//                        new String[] { serviceCert.getSubjectDN().getName() },
//                        e);
//            }
//            return this.createAttributeAssertion(doc, data ,encryptedKeyElem, nameId, config,
//                    crypto, creationTime, expirationTime);
//        } else {
//            try {
//                String subjectNameId = data.getPrincipal().getName();
//
//                SAMLNameIdentifier nameId = new SAMLNameIdentifier(
//                        subjectNameId, null, SAMLNameIdentifier.FORMAT_EMAIL);
//
//                // Create the ds:KeyValue element with the ds:X509Data
//                X509Certificate clientCert = data.getClientCert();
//
//                if(clientCert == null) {
//                    X509Certificate[] certs = crypto.getCertificates(
//                            data.getPrincipal().getName());
//                    clientCert = certs[0];
//                }
//
//                byte[] clientCertBytes = clientCert.getEncoded();
//
//                String base64Cert = Base64.encode(clientCertBytes);
//
//                Text base64CertText = doc.createTextNode(base64Cert);
//                Element x509CertElem = doc.createElementNS(WSConstants.SIG_NS,
//                        "X509Certificate");
//                x509CertElem.appendChild(base64CertText);
//                Element x509DataElem = doc.createElementNS(WSConstants.SIG_NS,
//                        "X509Data");
//                x509DataElem.appendChild(x509CertElem);
//
//                return this.createAuthAssertion(doc,
//                        SAMLSubject.CONF_HOLDER_KEY, nameId, x509DataElem,
//                        config, crypto, creationTime, expirationTime, data);
//            } catch (Exception e) {
//                throw new TrustException("samlAssertionCreationError", e);
//            }
//        }
//    }
//
//    /**
//     * Uses the <code>wst:AppliesTo</code> to figure out the certificate to
//     * encrypt the secret in the SAML token
//     *
//     * @param config
//     * @param crypto
//     * @param serviceAddress
//     *            The address of the service
//     * @return
//     * @throws WSSecurityException
//     */
//    private X509Certificate getServiceCert(SAMLTokenIssuerConfig config,
//            Crypto crypto, String serviceAddress) throws WSSecurityException {
//
//        if (serviceAddress != null && !"".equals(serviceAddress)) {
//            String alias = (String) config.trustedServices.get(serviceAddress);
//            if (alias != null) {
//                return crypto.getCertificates(alias)[0];
//            } else {
//                alias = (String) config.trustedServices.get("*");
//                return crypto.getCertificates(alias)[0];
//            }
//        } else {
//            String alias = (String) config.trustedServices.get("*");
//            return crypto.getCertificates(alias)[0];
//        }
//
//    }
//
//    /**
//     * Create the SAML assertion with the secret held in an
//     * <code>xenc:EncryptedKey</code>
//     *
//     * @param doc
//     * @param keyInfoContent
//     * @param config
//     * @param crypto
//     * @param notBefore
//     * @param notAfter
//     * @return
//     * @throws TrustException
//     */
//    private SAMLAssertion createAttributeAssertion(Document doc, RahasData data,
//            Element keyInfoContent, SAMLNameIdentifier subjectNameId, SAMLTokenIssuerConfig config,
//            Crypto crypto, Date notBefore, Date notAfter) throws TrustException {
//        try {
//            String[] confirmationMethods = new String[] { SAMLSubject.CONF_HOLDER_KEY };
//
//            Element keyInfoElem = doc.createElementNS(WSConstants.SIG_NS,
//                    "KeyInfo");
//            ((OMElement) keyInfoContent).declareNamespace(WSConstants.SIG_NS,
//                    WSConstants.SIG_PREFIX);
//            ((OMElement) keyInfoContent).declareNamespace(WSConstants.ENC_NS,
//                    WSConstants.ENC_PREFIX);
//
//            keyInfoElem.appendChild(keyInfoContent);
//
//            SAMLSubject subject = new SAMLSubject(subjectNameId, Arrays
//                    .asList(confirmationMethods), null, keyInfoElem);
//
//
//            SAMLAttribute[] attrs = null;
//            if (config.getCallbackHandler() != null) {
//                SAMLAttributeCallback cb = new SAMLAttributeCallback(data);
//                SAMLCallbackHandler handler = config.getCallbackHandler();
//                handler.handle(cb);
//                attrs = cb.getAttributes();
//            } else if (config.getCallbackHandlerName() != null
//                    && config.getCallbackHandlerName().trim().length() > 0) {
//                SAMLAttributeCallback cb = new SAMLAttributeCallback(data);
//                SAMLCallbackHandler handler = null;
//                MessageContext msgContext = data.getInMessageContext();
//                ClassLoader classLoader = msgContext.getAxisService().getClassLoader();
//                Class cbClass = null;
//                try {
//                    cbClass = Loader.loadClass(classLoader, config.getCallbackHandlerName());
//                } catch (ClassNotFoundException e) {
//                    throw new TrustException("cannotLoadPWCBClass", new String[]{config
//                            .getCallbackHandlerName()}, e);
//                }
//                try {
//                    handler = (SAMLCallbackHandler) cbClass.newInstance();
//                } catch (java.lang.Exception e) {
//                    throw new TrustException("cannotCreatePWCBInstance", new String[]{config
//                            .getCallbackHandlerName()}, e);
//                }
//                handler.handle(cb);
//                attrs = cb.getAttributes();
//            } else {
//                //TODO Remove this after discussing
//                SAMLAttribute attribute = new SAMLAttribute("Name",
//                        "https://rahas.apache.org/saml/attrns", null, -1, Arrays
//                        .asList(new String[]{"Colombo/Rahas"}));
//                attrs = new SAMLAttribute[]{attribute};
//            }
//
//            List attributeList = Arrays.asList(attrs);
//
//            // If ActAs element is present in the RST
//            if (data.getActAs() != null) {
//                SAMLAttribute actAsAttribute = new SAMLAttribute("ActAs",
//                        "https://rahas.apache.org/saml/attrns", null, -1, Arrays
//                        .asList(new String[]{data.getActAs()}));
//                attributeList.add(actAsAttribute);
//            }
//            SAMLAttributeStatement attrStmt = new SAMLAttributeStatement(
//                    subject, attributeList);
//
//            SAMLStatement[] statements = {attrStmt};
//
//            List<SAMLCondition> conditions = null;
//            if (StringUtils.isNotBlank(this.audienceRestriction)) {
//                SAMLAudienceRestrictionCondition audienceRestriction = new SAMLAudienceRestrictionCondition();
//                audienceRestriction.addAudience(this.audienceRestriction);
//
//                List<String> additionalAudiences =
//                        TokenIssuerUtil.getAdditionalAudiences(this.audienceRestriction);
//                for (String additionalAudience : additionalAudiences)
//                    audienceRestriction.addAudience(additionalAudience);
//
//                conditions = new ArrayList<SAMLCondition>();
//                conditions.add(audienceRestriction);
//            }
//
//            SAMLAssertion assertion = new SAMLAssertion(config.issuerName,
//                    notBefore, notAfter, conditions, null, Arrays.asList(statements));
//
//            // sign the assertion
//            X509Certificate[] issuerCerts = crypto
//                    .getCertificates(config.issuerKeyAlias);
//
//            String sigAlgo = SAMLUtils.getSignatureAlgorithm(config, issuerCerts);
//            java.security.Key issuerPK = crypto.getPrivateKey(
//                    config.issuerKeyAlias, config.issuerKeyPassword);
//            assertion.sign(sigAlgo, issuerPK, Arrays.asList(issuerCerts));
//
//            return assertion;
//        } catch (Exception e) {
//            throw new TrustException("samlAssertionCreationError", e);
//        }
//    }
//
//    /**
//     * @param doc
//     * @param confMethod
//     * @param subjectNameId
//     * @param keyInfoContent
//     * @param config
//     * @param crypto
//     * @param notBefore
//     * @param notAfter
//     * @return
//     * @throws TrustException
//     */
//    protected SAMLAssertion createAuthAssertion(Document doc, String confMethod,
//            SAMLNameIdentifier subjectNameId, Element keyInfoContent,
//            SAMLTokenIssuerConfig config, Crypto crypto, Date notBefore,
//            Date notAfter, RahasData data) throws TrustException {
//        try {
//            String[] confirmationMethods = new String[] { confMethod };
//
//            Element keyInfoElem = null;
//            if (keyInfoContent != null) {
//                keyInfoElem = doc
//                        .createElementNS(WSConstants.SIG_NS, "KeyInfo");
//                ((OMElement) keyInfoContent).declareNamespace(
//                        WSConstants.SIG_NS, WSConstants.SIG_PREFIX);
//                ((OMElement) keyInfoContent).declareNamespace(
//                        WSConstants.ENC_NS, WSConstants.ENC_PREFIX);
//
//                keyInfoElem.appendChild(keyInfoContent);
//            }
//
//            SAMLSubject subject = new SAMLSubject(subjectNameId, Arrays
//                    .asList(confirmationMethods), null, keyInfoElem);
//
//            List<SAMLStatement> statements = new ArrayList<SAMLStatement>();
//
//            SAMLAuthenticationStatement authStmt = new SAMLAuthenticationStatement(
//                    subject,
//                    SAMLAuthenticationStatement.AuthenticationMethod_Password,
//                    notBefore, null, null, null);
//            statements.add(authStmt);
//
//            // According to ws-trust specification <wst:claims> is an optional element, which requests a specific set
//            // of claims.
//            // These claims are retrieved by the AttributeCallbackHandler class.
//            SAMLStatement attrStatement = createSAMLAttributeStatement((SAMLSubject) subject.clone(), data, config);
//            if (attrStatement != null) {
//                statements.add(attrStatement);
//            }
//
//            List<SAMLCondition> conditions = null;
//            if (StringUtils.isNotBlank(this.audienceRestriction)) {
//                SAMLAudienceRestrictionCondition audienceRestriction = new SAMLAudienceRestrictionCondition();
//                audienceRestriction.addAudience(this.audienceRestriction);
//
//                List<String> additionalAudiences =
//                        TokenIssuerUtil.getAdditionalAudiences(this.audienceRestriction);
//                for (String additionalAudience : additionalAudiences)
//                    audienceRestriction.addAudience(additionalAudience);
//
//                conditions = new ArrayList<SAMLCondition>();
//                conditions.add(audienceRestriction);
//            }
//
//            SAMLAssertion assertion = new SAMLAssertion(config.issuerName,
//                    notBefore, notAfter, conditions, null, statements);
//
//            // sign the assertion
//            X509Certificate[] issuerCerts = crypto
//                    .getCertificates(config.issuerKeyAlias);
//
//            String sigAlgo = SAMLUtils.getSignatureAlgorithm(config, issuerCerts);
//            java.security.Key issuerPK = crypto.getPrivateKey(
//                    config.issuerKeyAlias, config.issuerKeyPassword);
//            assertion.sign(sigAlgo, issuerPK, Arrays.asList(issuerCerts));
//
//            return assertion;
//        } catch (Exception e) {
//            throw new TrustException("samlAssertionCreationError", e);
//        }
//    }
//
//    /**
//     * {@inheritDoc}
//     */
//    public String getResponseAction(RahasData data) throws TrustException {
//        return TrustUtil.getActionValue(data.getVersion(),
//                RahasConstants.RSTRC_ACTION_ISSUE_FINAL);
//    }
//
//    /**
//     * Create an ephemeral key
//     *
//     * @return The generated key as a byte array
//     * @throws TrustException
//     */
//    protected byte[] generateEphemeralKey(int keySize) throws TrustException {
//        try {
//            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//            byte[] temp = new byte[keySize / 8];
//            random.nextBytes(temp);
//            return temp;
//        } catch (Exception e) {
//            throw new TrustException("Error in creating the ephemeral key", e);
//        }
//    }
//
//    /**
//     * {@inheritDoc}
//     */
//    public void setConfigurationFile(String configFile) {
//        this.configFile = configFile;
//
//    }
//
//    /**
//     * {@inheritDoc}
//     */
//    public void setConfigurationElement(OMElement configElement) {
//        this.configElement = configElement;
//    }
//
//    /**
//     * {@inheritDoc}
//     */
//    public void setConfigurationParamName(String configParamName) {
//        this.configParamName = configParamName;
//    }
//
//    private SAMLAttributeStatement createSAMLAttributeStatement(SAMLSubject subject,
//                                                                RahasData rahasData,
//                                                                SAMLTokenIssuerConfig config)
//            throws TrustException {
//        try {
//            SAMLAttribute[] attrs = null;
//            if (config.getCallbackHandler() != null) {
//                SAMLAttributeCallback cb = new SAMLAttributeCallback(rahasData);
//                SAMLCallbackHandler handler = config.getCallbackHandler();
//                handler.handle(cb);
//                attrs = cb.getAttributes();
//            } else if (config.getCallbackHandlerName() != null
//                       && config.getCallbackHandlerName().trim().length() > 0) {
//                SAMLAttributeCallback cb = new SAMLAttributeCallback(rahasData);
//                SAMLCallbackHandler handler = null;
//                MessageContext msgContext = rahasData.getInMessageContext();
//                ClassLoader classLoader = msgContext.getAxisService().getClassLoader();
//                Class cbClass = null;
//                try {
//                    cbClass = Loader.loadClass(classLoader, config.getCallbackHandlerName());
//                } catch (ClassNotFoundException e) {
//                    throw new TrustException("cannotLoadPWCBClass",
//                                             new String[]{config.getCallbackHandlerName()}, e);
//                }
//                try {
//                    handler = (SAMLCallbackHandler) cbClass.newInstance();
//                } catch (Exception e) {
//                    throw new TrustException("cannotCreatePWCBInstance",
//                                             new String[]{config.getCallbackHandlerName()}, e);
//                }
//                handler.handle(cb);
//                attrs = cb.getAttributes();
//            }
//
//            //add attributes to the attribute statement
//            SAMLAttributeStatement attributeStatement = null;
//            if (!ArrayUtils.isEmpty(attrs)) {
//                attributeStatement = new SAMLAttributeStatement(subject, Arrays.asList(attrs));
//
//                if (log.isDebugEnabled()) {
//                    log.debug("SAML 1.1 attribute statement is constructed successfully.");
//                }
//            } else {
//                if (log.isDebugEnabled()) {
//                    log.debug("No requested attributes found for SAML 1.1 attribute statement");
//                }
//            }
//
//            return attributeStatement;
//        } catch (SAMLException e) {
//            throw new TrustException(e.getMessage(), e);
//        }
//    }
//
//}
