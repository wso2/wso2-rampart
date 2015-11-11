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

package org.apache.rampart.builder;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.client.Options;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.EncryptedKeyToken;
import org.apache.rahas.SimpleTokenStore;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rampart.RampartConstants;
import org.apache.rampart.RampartException;
import org.apache.rampart.RampartMessageData;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.SupportingPolicyData;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.IssuedToken;
import org.apache.ws.secpolicy.model.SecureConversationToken;
import org.apache.ws.secpolicy.model.SupportingToken;
import org.apache.ws.secpolicy.model.Token;
import org.apache.ws.secpolicy.model.UsernameToken;
import org.apache.ws.secpolicy.model.X509Token;
import org.apache.ws.security.KerberosTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.message.WSSecDKSign;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.message.WSSecKerberosToken;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecSignatureConfirmation;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Vector;

public abstract class BindingBuilder {
    private static Log log = LogFactory.getLog(BindingBuilder.class);

    private Element insertionLocation;

    protected String mainSigId = null;

    protected ArrayList encryptedTokensIdList = new ArrayList();

    protected Element timestampElement;

    protected Element mainRefListElement;

    /**
     * @param rmd
     */
    protected void addTimestamp(RampartMessageData rmd) {
        log.debug("Adding timestamp");

        WSSecTimestamp timestampBuilder = new WSSecTimestamp();
        timestampBuilder.setWsConfig(rmd.getConfig());

        timestampBuilder.setTimeToLive(RampartUtil.getTimeToLive(rmd));

        // add the Timestamp to the SOAP Enevelope

        timestampBuilder.build(rmd.getDocument(), rmd.getSecHeader());

        if (log.isDebugEnabled()) {
            log.debug("Timestamp id: " + timestampBuilder.getId());
        }
        rmd.setTimestampId(timestampBuilder.getId());

        this.timestampElement = timestampBuilder.getElement();
        log.debug("Adding timestamp: DONE");
    }

    /**
     * Add a UsernameToken to the security header
     * 
     * @param rmd
     * @return The <code>WSSecUsernameToken</code> instance
     * @throws RampartException
     */
    protected WSSecUsernameToken addUsernameToken(RampartMessageData rmd, UsernameToken token)
            throws RampartException {

        log.debug("Adding a UsernameToken");

        RampartPolicyData rpd = rmd.getPolicyData();

        // Get the user
        // First try options
        Options options = rmd.getMsgContext().getOptions();
        String user = options.getUserName();
        if (user == null || user.length() == 0) {
            // Then try RampartConfig
            if (rpd.getRampartConfig() != null) {
                user = rpd.getRampartConfig().getUser();
            }
        }

        if (user != null && !"".equals(user)) {
            if (log.isDebugEnabled()) {
                log.debug("User : " + user);
            }

            // If NoPassword property is set we don't need to set the password
            if (token.isNoPassword()) {
                WSSecUsernameToken utBuilder = new WSSecUsernameToken();
                utBuilder.setUserInfo(user, null);
                utBuilder.setPasswordType(null);
                if (rmd.getConfig() != null) {
                    utBuilder.setWsConfig(rmd.getConfig());
                }
                return utBuilder;
            }

            // Get the password

            // First check options object for a password
            String password = options.getPassword();

            if (password == null || password.length() == 0) {

                // Then try to get the password from the given callback handler
                CallbackHandler handler = RampartUtil.getPasswordCB(rmd);

                if (handler == null) {
                    // If the callback handler is missing
                    throw new RampartException("cbHandlerMissing");
                }

                WSPasswordCallback[] cb = { new WSPasswordCallback(user,
                        WSPasswordCallback.USERNAME_TOKEN) };
                try {
                    handler.handle(cb);
                } catch (Exception e) {
                    throw new RampartException("errorInGettingPasswordForUser",
                            new String[] { user }, e);
                }

                // get the password
                password = cb[0].getPassword();
            }

            if (log.isDebugEnabled()) {
                log.debug("Password : " + password);
            }

            if (password != null && !"".equals(password)) {
                // If the password is available then build the token

                WSSecUsernameToken utBuilder = new WSSecUsernameToken();
                if (rmd.getConfig() != null) {
                    utBuilder.setWsConfig(rmd.getConfig());
                }
                if (token.isHashPassword()) {
                    utBuilder.setPasswordType(WSConstants.PASSWORD_DIGEST);
                } else {
                    utBuilder.setPasswordType(WSConstants.PASSWORD_TEXT);
                }

                utBuilder.setUserInfo(user, password);

                return utBuilder;
            } else {
                // If there's no password then throw an exception
                throw new RampartException("noPasswordForUser", new String[] { user });
            }

        } else {
            log.debug("No user value specified in the configuration");
            throw new RampartException("userMissing");
        }

    }

    /**
     * @param rmd
     * @param token
     * @return
     * @throws WSSecurityException
     * @throws RampartException
     */
    protected WSSecEncryptedKey getEncryptedKeyBuilder(RampartMessageData rmd, Token token)
            throws RampartException {

        RampartPolicyData rpd = rmd.getPolicyData();
        Document doc = rmd.getDocument();

        WSSecEncryptedKey encrKey = new WSSecEncryptedKey();

        try {
            RampartUtil.setKeyIdentifierType(rmd, encrKey, token);
            RampartUtil.setEncryptionUser(rmd, encrKey);
            encrKey.setKeySize(rpd.getAlgorithmSuite().getMaximumSymmetricKeyLength());
            encrKey.setKeyEncAlgo(rpd.getAlgorithmSuite().getAsymmetricKeyWrap());

            encrKey.prepare(
                    doc,
                    RampartUtil.getEncryptionCrypto(rpd.getRampartConfig(),
                            rmd.getCustomClassLoader()));

            return encrKey;
        } catch (WSSecurityException e) {
            throw new RampartException("errorCreatingEncryptedKey", e);
        }
    }

    // Deprecated after 1.5 release
    @Deprecated
    protected WSSecSignature getSignatureBuider(RampartMessageData rmd, Token token)
            throws RampartException {
        return getSignatureBuilder(rmd, token, null);
    }

    // Deprecated after 1.5 release
    @Deprecated
    protected WSSecSignature getSignatureBuider(RampartMessageData rmd, Token token,
            String userCertAlias) throws RampartException {
        return getSignatureBuilder(rmd, token, userCertAlias);
    }

    protected WSSecSignature getSignatureBuilder(RampartMessageData rmd, Token token)
            throws RampartException {
        return getSignatureBuilder(rmd, token, null);
    }

    protected WSSecSignature getSignatureBuilder(RampartMessageData rmd, Token token,
            String userCertAlias) throws RampartException {

        RampartPolicyData rpd = rmd.getPolicyData();

        WSSecSignature sig = new WSSecSignature();
        checkForX509PkiPath(sig, token);
        sig.setWsConfig(rmd.getConfig());

        if (log.isDebugEnabled()) {
            log.debug("Token inclusion: " + token.getInclusion());
        }

        RampartUtil.setKeyIdentifierType(rmd, sig, token);

        String user = null;

        if (userCertAlias != null) {
            user = userCertAlias;
        }

        // Get the user - First check whether userCertAlias present
        if (user == null) {
            user = rpd.getRampartConfig().getUserCertAlias();
        }

        // If userCertAlias is not present, use user property as Alias

        if (user == null) {
            user = rpd.getRampartConfig().getUser();
        }

        String password = null;

        if (user != null && !"".equals(user)) {
            if (log.isDebugEnabled()) {
                log.debug("User : " + user);
            }

            // Get the password
            CallbackHandler handler = RampartUtil.getPasswordCB(rmd);

            if (handler == null) {
                // If the callback handler is missing
                throw new RampartException("cbHandlerMissing");
            }

            WSPasswordCallback[] cb = { new WSPasswordCallback(user, WSPasswordCallback.SIGNATURE) };

            try {
                handler.handle(cb);
                if (cb[0].getPassword() != null && !"".equals(cb[0].getPassword())) {
                    password = cb[0].getPassword();
                    if (log.isDebugEnabled()) {
                        log.debug("Password : " + password);
                    }
                } else {
                    // If there's no password then throw an exception
                    throw new RampartException("noPasswordForUser", new String[] { user });
                }
            } catch (IOException e) {
                throw new RampartException("errorInGettingPasswordForUser", new String[] { user },
                        e);
            } catch (UnsupportedCallbackException e) {
                throw new RampartException("errorInGettingPasswordForUser", new String[] { user },
                        e);
            }

        } else {
            log.debug("No user value specified in the configuration");
			if (token instanceof IssuedToken) {
				throw new RampartException("userMissing");
			}
        }

        sig.setUserInfo(user, password);
        sig.setSignatureAlgorithm(rpd.getAlgorithmSuite().getAsymmetricSignature());
        sig.setSigCanonicalization(rpd.getAlgorithmSuite().getInclusiveC14n());

        try {
            sig.prepare(
                    rmd.getDocument(),
                    RampartUtil.getSignatureCrypto(rpd.getRampartConfig(),
                            rmd.getCustomClassLoader()), rmd.getSecHeader());
        } catch (WSSecurityException e) {
            throw new RampartException("errorInSignatureWithX509Token", e);
        }

        return sig;
    }

    /**
     * @param rmd
     * @param suppTokens
     * @throws RampartException
     */
    protected HashMap handleSupportingTokens(RampartMessageData rmd, SupportingToken suppTokens)
            throws RampartException {

        // Create the list to hold the tokens
        HashMap endSuppTokMap = new HashMap();

        if (suppTokens != null && suppTokens.getTokens() != null
                && suppTokens.getTokens().size() > 0) {
            log.debug("Processing supporting tokens");

            ArrayList tokens = suppTokens.getTokens();
            for (Iterator iter = tokens.iterator(); iter.hasNext();) {
                Token token = (Token) iter.next();
                org.apache.rahas.Token endSuppTok = null;
                if (token instanceof IssuedToken && rmd.isInitiator()) {
                    String id = RampartUtil.getIssuedToken(rmd, (IssuedToken) token);
                    try {
                        endSuppTok = rmd.getTokenStorage().getToken(id);
                    } catch (TrustException e) {
                        throw new RampartException("errorInRetrievingTokenId", new String[] { id },
                                e);
                    }

                    if (endSuppTok == null) {
                        throw new RampartException("errorInRetrievingTokenId", new String[] { id });
                    }

                    // Add the token to the header
                    Element siblingElem = RampartUtil.insertSiblingAfter(rmd,
                            this.getInsertionLocation(), (Element) endSuppTok.getToken());
                    this.setInsertionLocation(siblingElem);

                    if (suppTokens.isEncryptedToken()) {
                        this.encryptedTokensIdList.add(endSuppTok.getId());
                    }

                    //Create a SecurityTokenReference and add the token
                    Element strElem = TrustUtil.createSecurityTokenReferenceWithTokenType(rmd.getSecHeader()
                            .getSecurityHeader().getOwnerDocument(), id, "http://docs.oasis-open" +
                            ".org/wss/oasis-wss-saml-token-profile-1.1#SAMLID", "http://docs.oasis-open" +
                            ".org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
                    Element strElemInserted = RampartUtil.insertSiblingAfter(rmd, siblingElem, strElem);

                    this.setInsertionLocation(strElemInserted);
                    String elementID = RampartUtil.addWsuIdToElement((OMElement)strElemInserted);

                    // Add the extracted token
                    endSuppTokMap.put(elementID, strElemInserted);


                } else if (token instanceof X509Token) {

                    // We have to use a cert
                    // Prepare X509 signature
                    WSSecSignature sig = this.getSignatureBuilder(rmd, token);
                    Element bstElem = sig.getBinarySecurityTokenElement();
                    if (bstElem != null) {
                        bstElem = RampartUtil.insertSiblingAfter(rmd, this.getInsertionLocation(),
                                bstElem);
                        this.setInsertionLocation(bstElem);

                        SupportingPolicyData supportingPolcy = new SupportingPolicyData();
                        supportingPolcy.build(suppTokens);
                        supportingPolcy.setSignatureToken(token);
                        supportingPolcy.setEncryptionToken(token);
                        rmd.getPolicyData().addSupportingPolicyData(supportingPolcy);

                        if (suppTokens.isEncryptedToken()) {
                            this.encryptedTokensIdList.add(sig.getBSTTokenId());
                        }
                    }
                    endSuppTokMap.put(token, sig);

                } else if (token instanceof UsernameToken) {
                    WSSecUsernameToken utBuilder = addUsernameToken(rmd, (UsernameToken) token);

                    utBuilder.prepare(rmd.getDocument());

                    // Add the UT
                    Element elem = utBuilder.getUsernameTokenElement();
                    elem = RampartUtil.insertSiblingAfter(rmd, this.getInsertionLocation(), elem);

                    if (suppTokens.isEncryptedToken()) {
                        encryptedTokensIdList.add(utBuilder.getId());
                    }

                    // Move the insert location to the next element
                    this.setInsertionLocation(elem);
                    Date now = new Date();
                    try {
                        org.apache.rahas.Token tempTok = new org.apache.rahas.Token(
                                utBuilder.getId(), (OMElement) elem, now, new Date(
                                        now.getTime() + 300000));
                        endSuppTokMap.put(token, tempTok);
                    } catch (TrustException e) {
                        throw new RampartException("errorCreatingRahasToken", e);
                    }
                }
            }
        }

        return endSuppTokMap;
    }

    /**
     * @param tokenMap
     * @param sigParts
     * @throws RampartException
     */
    protected Vector addSignatureParts(HashMap tokenMap, Vector sigParts) throws RampartException {

        Set entrySet = tokenMap.entrySet();

        for (Iterator iter = entrySet.iterator(); iter.hasNext();) {
            Object tempTok = ((Entry) iter.next()).getValue();
            WSEncryptionPart part = null;

            if (tempTok instanceof org.apache.rahas.Token) {

                part = new WSEncryptionPart(((org.apache.rahas.Token) tempTok).getId());

            } else if (tempTok instanceof WSSecSignature) {
                WSSecSignature tempSig = (WSSecSignature) tempTok;
                if (tempSig.getBSTTokenId() != null) {
                    part = new WSEncryptionPart(tempSig.getBSTTokenId());
                }
            } else if (tempTok instanceof OMElement && SecurityTokenReference.SECURITY_TOKEN_REFERENCE.equals(
                    ((OMElement) tempTok).getLocalName())) {
                String id = ((OMElement) tempTok).getAttributeValue(new QName(WSConstants.WSU_NS, "Id", "wsu"));
                if (id != null) {
                    part = new WSEncryptionPart(id);
                    part.setName(SecurityTokenReference.SECURITY_TOKEN_REFERENCE);
                }
            } else {

                throw new RampartException("UnsupportedTokenInSupportingToken");
            }
            sigParts.add(part);
        }

        return sigParts;
    }

    public Element getInsertionLocation() {
        return insertionLocation;
    }

    public void setInsertionLocation(Element insertionLocation) {
        this.insertionLocation = insertionLocation;
    }

    protected Vector doEndorsedSignatures(RampartMessageData rmd, HashMap tokenMap)
            throws RampartException {

        Set tokenSet = tokenMap.keySet();

        Vector sigValues = new Vector();

        for (Iterator iter = tokenSet.iterator(); iter.hasNext();) {

            Token token = (Token) iter.next();

            Object tempTok = tokenMap.get(token);

            Vector sigParts = new Vector();
            sigParts.add(new WSEncryptionPart(this.mainSigId));

            if (tempTok instanceof org.apache.rahas.Token) {
                org.apache.rahas.Token tok = (org.apache.rahas.Token) tempTok;
                if (rmd.getPolicyData().isTokenProtection()) {
                    sigParts.add(new WSEncryptionPart(tok.getId()));
                }

                this.doSymmSignature(rmd, token, (org.apache.rahas.Token) tempTok, sigParts);

            } else if (tempTok instanceof WSSecSignature) {
                WSSecSignature sig = (WSSecSignature) tempTok;
                if (rmd.getPolicyData().isTokenProtection() && sig.getBSTTokenId() != null) {
                    sigParts.add(new WSEncryptionPart(sig.getBSTTokenId()));
                }

                try {
                    sig.addReferencesToSign(sigParts, rmd.getSecHeader());
                    sig.computeSignature();

                    this.setInsertionLocation(RampartUtil.insertSiblingAfter(rmd,
                            this.getInsertionLocation(), sig.getSignatureElement()));

                } catch (WSSecurityException e) {
                    throw new RampartException("errorInSignatureWithX509Token", e);
                }
                sigValues.add(sig.getSignatureValue());
            }
        }

        return sigValues;

    }

    protected byte[] doSymmSignature(RampartMessageData rmd, Token policyToken,
            org.apache.rahas.Token tok, Vector sigParts) throws RampartException {

        Document doc = rmd.getDocument();

        RampartPolicyData rpd = rmd.getPolicyData();

        if (policyToken.isDerivedKeys()) {
            try {
                WSSecDKSign dkSign = new WSSecDKSign();

                // Check whether it is security policy 1.2 and use the secure conversation
                // accordingly
                if (SPConstants.SP_V12 == policyToken.getVersion()) {
                    dkSign.setWscVersion(ConversationConstants.VERSION_05_12);
                }

                // Check for whether the token is attached in the message or not
                boolean attached = false;

                if (SPConstants.INCLUDE_TOEKN_ALWAYS == policyToken.getInclusion()
                        || SPConstants.INCLUDE_TOKEN_ONCE == policyToken.getInclusion()
                        || (rmd.isInitiator() && SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT == policyToken
                                .getInclusion())) {
                    attached = true;
                }

                // Setting the AttachedReference or the UnattachedReference according to the flag
                OMElement ref;
                if (attached == true) {
                    ref = tok.getAttachedReference();
                } else {
                    ref = tok.getUnattachedReference();
                }

                if (ref != null) {
                    dkSign.setExternalKey(tok.getSecret(),
                            (Element) doc.importNode((Element) ref, true));
                } else if (!rmd.isInitiator() && policyToken.isDerivedKeys()) {

                    // If the Encrypted key used to create the derived key is not
                    // attached use key identifier as defined in WSS1.1 section
                    // 7.7 Encrypted Key reference
                    SecurityTokenReference tokenRef = new SecurityTokenReference(doc);
                    if (tok instanceof EncryptedKeyToken) {
                        tokenRef.setKeyIdentifierEncKeySHA1(((EncryptedKeyToken) tok).getSHA1());
                        ;
                    }
                    dkSign.setExternalKey(tok.getSecret(), tokenRef.getElement());

                } else {
                    dkSign.setExternalKey(tok.getSecret(), tok.getId());
                }

                // Set the algo info
                dkSign.setSignatureAlgorithm(rpd.getAlgorithmSuite().getSymmetricSignature());
                dkSign.setDerivedKeyLength(rpd.getAlgorithmSuite().getSignatureDerivedKeyLength() / 8);
                if (tok instanceof EncryptedKeyToken) {
                    // Set the value type of the reference
                    dkSign.setCustomValueType(WSConstants.SOAPMESSAGE_NS11 + "#"
                            + WSConstants.ENC_KEY_VALUE_TYPE);
                }

                dkSign.prepare(doc, rmd.getSecHeader());

                if (rpd.isTokenProtection()) {

                    // Hack to handle reference id issues
                    // TODO Need a better fix
                    String sigTokId = tok.getId();
                    if (sigTokId.startsWith("#")) {
                        sigTokId = sigTokId.substring(1);
                    }
                    sigParts.add(new WSEncryptionPart(sigTokId));
                }

                dkSign.setParts(sigParts);

                dkSign.addReferencesToSign(sigParts, rmd.getSecHeader());

                // Do signature
                dkSign.computeSignature();

                // Add elements to header

                if (rpd.getProtectionOrder().equals(SPConstants.ENCRYPT_BEFORE_SIGNING)
                        && this.getInsertionLocation() == null) {
                    this.setInsertionLocation(RampartUtil

                    .insertSiblingBefore(rmd, this.mainRefListElement, dkSign.getdktElement()));

                    this.setInsertionLocation(RampartUtil.insertSiblingAfter(rmd,
                            this.getInsertionLocation(), dkSign.getSignatureElement()));
                } else {
                    this.setInsertionLocation(RampartUtil

                    .insertSiblingAfter(rmd, this.getInsertionLocation(), dkSign.getdktElement()));

                    this.setInsertionLocation(RampartUtil.insertSiblingAfter(rmd,
                            this.getInsertionLocation(), dkSign.getSignatureElement()));
                }

                return dkSign.getSignatureValue();

            } catch (ConversationException e) {
                throw new RampartException("errorInDerivedKeyTokenSignature", e);
            } catch (WSSecurityException e) {
                throw new RampartException("errorInDerivedKeyTokenSignature", e);
            }
        } else {
            try {
                WSSecSignature sig = new WSSecSignature();
                sig.setWsConfig(rmd.getConfig());

                // If a EncryptedKeyToken is used, set the correct value type to
                // be used in the wsse:Reference in ds:KeyInfo
                if (policyToken instanceof X509Token) {
                    if (rmd.isInitiator()) {
                        sig.setCustomTokenValueType(WSConstants.SOAPMESSAGE_NS11 + "#"
                                + WSConstants.ENC_KEY_VALUE_TYPE);
                        sig.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
                    } else {
                        // the tok has to be an EncryptedKey token
                        sig.setEncrKeySha1value(((EncryptedKeyToken) tok).getSHA1());
                        sig.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
                    }

                } else if (policyToken instanceof IssuedToken) {
					if ("urn:oasis:names:tc:SAML:2.0:assertion".equals(((IssuedToken) policyToken)
							.getRstTokenType())) {
						sig.setCustomTokenValueType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID");
					} else {
						sig.setCustomTokenValueType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID");
					}
					sig.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
                }

                String sigTokId;

                if (policyToken instanceof SecureConversationToken) {
                    sig.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
                    OMElement ref = tok.getAttachedReference();
                    if (ref == null) {
                        ref = tok.getUnattachedReference();
                    }

                    if (ref != null) {
                        sigTokId = SimpleTokenStore.getIdFromSTR(ref);
                    } else {
                        sigTokId = tok.getId();
                    }
                } else {
                    sigTokId = tok.getId();
                }

                // Hack to handle reference id issues
                // TODO Need a better fix
                if (sigTokId.startsWith("#")) {
                    sigTokId = sigTokId.substring(1);
                }

                sig.setCustomTokenId(sigTokId);
                sig.setSecretKey(tok.getSecret());

				if (tok.getSecret() == null) {
					sig.setUserInfo(
							rpd.getRampartConfig().getUser(),
							rpd.getRampartConfig()
									.getSigCryptoConfig()
									.getProp()
									.getProperty(
											"org.wso2.carbon.security.crypto.private.key.password"));
					sig.setSignatureAlgorithm(rpd.getAlgorithmSuite().getAsymmetricSignature());
				} else {
					sig.setSignatureAlgorithm(rpd.getAlgorithmSuite().getSymmetricSignature());
				}
                
                sig.prepare(
                        rmd.getDocument(),
                        RampartUtil.getSignatureCrypto(rpd.getRampartConfig(),
                                rmd.getCustomClassLoader()), rmd.getSecHeader());

                sig.setParts(sigParts);
                sig.addReferencesToSign(sigParts, rmd.getSecHeader());

                // Do signature
                sig.computeSignature();

                if (rpd.getProtectionOrder().equals(SPConstants.ENCRYPT_BEFORE_SIGNING)
                        && this.getInsertionLocation() == null) {
                    this.setInsertionLocation(RampartUtil.insertSiblingBefore(rmd,
                            this.mainRefListElement, sig.getSignatureElement()));
                } else {
                    this.setInsertionLocation(RampartUtil.insertSiblingAfter(rmd,
                            this.getInsertionLocation(), sig.getSignatureElement()));
                }

                return sig.getSignatureValue();

            } catch (WSSecurityException e) {
                throw new RampartException("errorInSignatureWithACustomToken", e);
            }

        }
    }

    /**
     * Get hold of the token from the token storage
     * 
     * @param rmd
     * @param tokenId
     * @return token from the token storage
     * @throws RampartException
     */
    protected org.apache.rahas.Token getToken(RampartMessageData rmd, String tokenId)
            throws RampartException {
        org.apache.rahas.Token tok = null;
        try {
            tok = rmd.getTokenStorage().getToken(tokenId);
        } catch (TrustException e) {
            throw new RampartException("errorInRetrievingTokenId", new String[] { tokenId }, e);
        }

        if (tok == null) {
            throw new RampartException("errorInRetrievingTokenId", new String[] { tokenId });
        }
        return tok;
    }

    protected void addSignatureConfirmation(RampartMessageData rmd, Vector sigParts) {

        if (!rmd.getPolicyData().isSignatureConfirmation()) {

            // If we don't require sig confirmation simply go back :-)
            return;
        }

        Document doc = rmd.getDocument();

        Vector results = (Vector) rmd.getMsgContext().getProperty(WSHandlerConstants.RECV_RESULTS);
        /*
         * loop over all results gathered by all handlers in the chain. For each handler result get
         * the various actions. After that loop we have all signature results in the
         * signatureActions vector
         */
		Vector signatureActions = new Vector();
		for (int i = 0; i < results.size(); i++) {
			WSHandlerResult wshResult = (WSHandlerResult) results.get(i);

			WSSecurityUtil.fetchAllActionResults(wshResult.getResults(), WSConstants.SIGN,
					signatureActions);
			WSSecurityUtil.fetchAllActionResults(wshResult.getResults(), WSConstants.ST_SIGNED,
					signatureActions);
			WSSecurityUtil.fetchAllActionResults(wshResult.getResults(), WSConstants.UT_SIGN,
					signatureActions);
			WSSecurityUtil.fetchAllActionResults(wshResult.getResults(), WSConstants.KERBEROS_SIGN,
					signatureActions);
		}

        // prepare a SignatureConfirmation token
        WSSecSignatureConfirmation wsc = new WSSecSignatureConfirmation();
        if (signatureActions.size() > 0) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Confirmation: number of Signature results: "
                        + signatureActions.size());
            }
            for (int i = 0; i < signatureActions.size(); i++) {
                WSSecurityEngineResult wsr = (WSSecurityEngineResult) signatureActions.get(i);
                byte[] sigVal = (byte[]) wsr.get(WSSecurityEngineResult.TAG_SIGNATURE_VALUE);
                wsc.setSignatureValue(sigVal);
                wsc.prepare(doc);
                RampartUtil.appendChildToSecHeader(rmd, wsc.getSignatureConfirmationElement());
                if (sigParts != null) {
                    sigParts.add(new WSEncryptionPart(wsc.getId()));
                }
            }
        } else {
            // No Sig value
            wsc.prepare(doc);
            RampartUtil.appendChildToSecHeader(rmd, wsc.getSignatureConfirmationElement());
            if (sigParts != null) {
                sigParts.add(new WSEncryptionPart(wsc.getId()));
            }
        }
    }

    protected WSSecKerberosToken getKerberosTokenBuilder(RampartMessageData rmd, Token token)
            throws RampartException {

        RampartPolicyData rpd = rmd.getPolicyData();
        KerberosConfig krbConfig = rpd.getRampartConfig().getKerberosConfig();

        if (krbConfig == null || krbConfig.getProp() == null) {
            throw new RampartException("noKerberosConfigDefined");
        }

        WSSecKerberosToken krb = new WSSecKerberosToken();
        krb.setWsConfig(rmd.getConfig());

        log.debug("Token inclusion: " + token.getInclusion());

        RampartUtil.setKeyIdentifierType(rmd, krb, token);

        String user = null;
        String passwordFromConfig = null;
        String clientPricipal = null;
        String servicePrincipal = null;
        String password = null;
        String service = null;

        clientPricipal = (String) rmd.getMsgContext().getProperty(
                KerberosConfig.CLIENT_PRINCIPLE_NAME);
        servicePrincipal = (String) rmd.getMsgContext().getProperty(
                KerberosConfig.SERVICE_PRINCIPLE_NAME);

		if (clientPricipal == null || servicePrincipal == null || rmd.isInitiator()) {
			// Get the user from kerberos configuration
			user = krbConfig.getProp().getProperty(KerberosConfig.CLIENT_PRINCIPLE_NAME);
			passwordFromConfig = krbConfig.getProp().getProperty(
					KerberosConfig.CLIENT_PRINCIPLE_PASSWORD);
			if (passwordFromConfig == null) {
				passwordFromConfig = krbConfig.getProp().getProperty(
						KerberosConfig.SERVICE_PRINCIPLE_PASSWORD);
			}

            // If kerberos user is not present, use user property as Alias
            if (user == null) {
                user = rpd.getRampartConfig().getUser();
            }

            if (user != null && !"".equals(user)) {
                log.debug("User : " + user);

                // Get the password
                CallbackHandler handler = RampartUtil.getPasswordCB(rmd);

                if (handler != null) {
                    WSPasswordCallback[] cb = { new WSPasswordCallback(user,
                            WSPasswordCallback.KERBEROS_TOKEN) };
                    try {
                        handler.handle(cb);
                        if (cb[0].getPassword() != null && !"".equals(cb[0].getPassword())) {
                            password = cb[0].getPassword();
                            log.debug("Password : " + password);
                        } else {
                            password = passwordFromConfig;
                        }
                    } catch (IOException e) {
                        throw new RampartException("errorInGettingPasswordForUser",
                                new String[] { user }, e);
                    } catch (UnsupportedCallbackException e) {
                        throw new RampartException("errorInGettingPasswordForUser",
                                new String[] { user }, e);
                    }
                } else {
                    password = passwordFromConfig;
                }

            }
            service = krbConfig.getProp().getProperty(KerberosConfig.SERVICE_PRINCIPLE_NAME);
        } else {
            user = clientPricipal;
            service = servicePrincipal;
        }

        krb.setUserInfo(user, password);
        krb.setServicePrincipalName(service);

        if (!rmd.isInitiator()) {
            krb.setReceiver(true);
        }

        try {
            krb.build(rmd.getDocument(), rmd.getSecHeader());
        } catch (WSSecurityException e) {
            throw new RampartException("errorInBuilingKereberosToken", e);
        }

        if (!rmd.isInitiator()) {
            setKerberosToken(rmd, krb);
        }

        return krb;
    }

    protected void initializeTokens(RampartMessageData rmd) throws RampartException {
        RampartPolicyData rpd = rmd.getPolicyData();
        MessageContext msgContext = rmd.getMsgContext();
        if (!msgContext.isServerSide()) {
            if (log.isDebugEnabled())
                log.debug("Processing symmetric binding: Setting up encryption token and signature token");
            Token sigTok = null;
            Token encrTok = null;
            if (rpd.isAsymmetricBinding()) {
                sigTok = rpd.getInitiatorToken();
                encrTok = rpd.getRecipientToken();
            } else {
                sigTok = rpd.getSignatureToken();
                encrTok = rpd.getEncryptionToken();
            }
            if (sigTok instanceof IssuedToken) {
                log.debug("SignatureToken is an IssuedToken");
                if (rmd.getIssuedSignatureTokenId() == null) {
                    log.debug("No Issuedtoken found, requesting a new token");
                    IssuedToken issuedToken = (IssuedToken) sigTok;
                    String id = RampartUtil.getIssuedToken(rmd, issuedToken);
                    rmd.setIssuedSignatureTokenId(id);
                }
            } else if (sigTok instanceof SecureConversationToken) {
                log.debug("SignatureToken is a SecureConversationToken");
                String secConvTokenId = rmd.getSecConvTokenId();
                String action = msgContext.getOptions().getAction();
                boolean cancelReqResp = action
                        .equals("http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel")
                        || action
                            .equals("http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel")
                        || action
                            .equals("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel")
                        || action
                            .equals("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel");
                if (secConvTokenId != null && cancelReqResp)
                    try {
                        rmd.getTokenStorage().getToken(secConvTokenId).setState(3);
                        msgContext.setProperty("sctID", secConvTokenId);
                        String contextIdentifierKey = RampartUtil
                                .getContextIdentifierKey(msgContext);
                        RampartUtil.getContextMap(msgContext).remove(contextIdentifierKey);
                    } catch (TrustException e) {
                        throw new RampartException("errorExtractingToken");
                    }
                if (secConvTokenId == null || secConvTokenId != null
                        && !RampartUtil.isTokenValid(rmd, secConvTokenId) && !cancelReqResp) {
                    log.debug("No SecureConversationToken found, requesting a new token");
                    SecureConversationToken secConvTok = (SecureConversationToken) sigTok;
                    try {
                        String id = RampartUtil.getSecConvToken(rmd, secConvTok);
                        rmd.setSecConvTokenId(id);
                    } catch (TrustException e) {
                        throw new RampartException("errorInObtainingSct", e);
                    }
                }
            }
            if (sigTok instanceof IssuedToken && sigTok.equals(encrTok)) {
                log.debug("Symmetric binding uses a ProtectionToken, both SignatureToken and EncryptionToken are the same");
                rmd.setIssuedEncryptionTokenId(rmd.getIssuedEncryptionTokenId());
            } else {
                log.debug("Obtaining the Encryption Token");
                if (rmd.getIssuedEncryptionTokenId() != null) {
                    log.debug("EncrytionToken not alredy set");
                    IssuedToken issuedToken = (IssuedToken) encrTok;
                    String id = RampartUtil.getIssuedToken(rmd, issuedToken);
                    rmd.setIssuedEncryptionTokenId(id);
                }
            }
        }
    }

    /**
     * 
     * @param rmd
     * @param krbToken
     * @throws RampartException
     */
    private void setKerberosToken(RampartMessageData rmd, WSSecKerberosToken krbToken)
            throws RampartException {
        Vector results = (Vector) rmd.getMsgContext().getProperty(WSHandlerConstants.RECV_RESULTS);
        for (int i = 0; i < results.size(); i++) {
            WSHandlerResult rResult = (WSHandlerResult) results.get(i);
            Vector wsSecEngineResults = rResult.getResults();
            for (int j = 0; j < wsSecEngineResults.size(); j++) {
                WSSecurityEngineResult wser = (WSSecurityEngineResult) wsSecEngineResults.get(j);
                Integer actInt = (Integer) wser.get(WSSecurityEngineResult.TAG_ACTION);
                if (actInt.intValue() == org.apache.ws.security.WSConstants.KERBEROS_SIGN) {
                    KerberosTokenPrincipal principal = (KerberosTokenPrincipal) wser
                            .get(WSSecurityEngineResult.TAG_PRINCIPAL);
                    BinarySecurity token;
                    try {
                        token = new BinarySecurity(principal.getTokenElement());
                        krbToken.setBSTToken(token);
                    } catch (WSSecurityException e) {
                        throw new RampartException("errorExtractingKereberosToken");
                    }
                }
            }
        }
    }

    private void checkForX509PkiPath(WSSecSignature sig, Token token) {
        if (token instanceof X509Token) {
            X509Token x509Token = (X509Token) token;
            if (x509Token.getTokenVersionAndType().equals(Constants.WSS_X509_PKI_PATH_V1_TOKEN10)
                    || x509Token.getTokenVersionAndType().equals(
                            Constants.WSS_X509_PKI_PATH_V1_TOKEN11)) {
                sig.setUseSingleCertificate(false);
            }
        }
    }

}
