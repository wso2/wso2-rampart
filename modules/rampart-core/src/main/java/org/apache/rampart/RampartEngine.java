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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFault;
import org.apache.axiom.soap.SOAPFaultCode;
import org.apache.axiom.soap.SOAPFaultSubCode;
import org.apache.axiom.soap.SOAPFaultValue;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.Token;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.impl.util.SAML2KeyInfo;
import org.apache.rahas.impl.util.SAML2Utils;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.rampart.util.Axis2Util;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.IssuedToken;
import org.apache.ws.security.KerberosTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
//import org.apache.ws.security.saml.SAMLKeyInfo;
//import org.apache.ws.security.saml.SAMLUtil;
//import org.opensaml.SAMLAssertion;
//import org.opensaml.SAMLSubject;
//import org.opensaml.SAMLSubjectStatement;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmationData;

import javax.xml.namespace.QName;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

public class RampartEngine {

    private static final Log log = LogFactory.getLog(RampartEngine.class);
    private static final Log tlog = LogFactory.getLog(RampartConstants.TIME_LOG);
    private static ServiceNonceCache serviceNonceCache = new ServiceNonceCache();

    public Vector process(MessageContext msgCtx) throws WSSPolicyException, RampartException,
            WSSecurityException, AxisFault {

        boolean doDebug = log.isDebugEnabled();
        boolean dotDebug = tlog.isDebugEnabled();

        log.debug("Enter process(MessageContext msgCtx)");

        RampartMessageData rmd = new RampartMessageData(msgCtx, false);

        RampartPolicyData rpd = rmd.getPolicyData();

         if (log.isDebugEnabled()) {
            if (rpd != null && rpd.getRampartConfig() != null
                && rpd.getRampartConfig().isOptimizeMessageProcessingForTransportBinding()) {
                log.debug("Optimized Message Processing enabled for transport binding.");
            }
        }

        msgCtx.setProperty(RampartMessageData.RAMPART_POLICY_DATA, rpd);

        RampartUtil.validateTransport(rmd);

        // If there is no policy information return immediately
        if (rpd == null) {
            return null;
        }

        // TODO these checks have to be done before the convertion to avoid unnecessary convertion
        // to LLOM -> DOOM
        // If the message is a security fault or no security
        // header required by the policy
        if (isSecurityFault(rmd) || !RampartUtil.isSecHeaderRequired(rpd, rmd.isInitiator(), true)) {
            SOAPEnvelope env = Axis2Util.getSOAPEnvelopeFromDOMDocument(rmd.getDocument(), true);

            // Convert back to llom since the inflow cannot use llom
            msgCtx.setEnvelope(env);
            Axis2Util.useDOOM(false);
            log.debug("Return process MessageContext msgCtx)");
            return null;
        }

        Vector results = null;

        WSSecurityEngine engine = new WSSecurityEngine();

        ValidatorData data = new ValidatorData(rmd);

        SOAPHeader header = rmd.getMsgContext().getEnvelope().getHeader();
        if (header == null) {
            throw new RampartException("missingSOAPHeader");
        }

        if ((rpd.isSignBody() || rpd.isEntireHeadersAndBodySignatures()) && !isValidHeaderForSignedBody(header)) {
            throw new RampartException("Duplicate Body element within the header");
        }

        ArrayList headerBlocks = header.getHeaderBlocksWithNSURI(WSConstants.WSSE_NS);
        SOAPHeaderBlock secHeader = null;
        // Issue is axiom - a returned collection must not be null
        if (headerBlocks != null) {
            Iterator headerBlocksIterator = headerBlocks.iterator();
            while (headerBlocksIterator.hasNext()) {
                SOAPHeaderBlock elem = (SOAPHeaderBlock) headerBlocksIterator.next();
                if (elem.getLocalName().equals(WSConstants.WSSE_LN)) {
                    secHeader = elem;
                    break;
                }
            }
        }

        if (secHeader == null) {
            throw new RampartException("missingSecurityHeader");
        }

        long t0 = 0, t1 = 0, t2 = 0, t3 = 0;
        if (dotDebug) {
            t0 = System.currentTimeMillis();
        }

        String actorValue = secHeader.getAttributeValue(new QName(rmd.getSoapConstants()
                .getEnvelopeURI(), "actor"));

        if (actorValue == null) {
               actorValue = secHeader.getAttributeValue(new QName(rmd.getSoapConstants()
                    .getEnvelopeURI(), "role"));
        }

        Crypto signatureCrypto = RampartUtil.getSignatureCrypto(rpd.getRampartConfig(), msgCtx
                .getAxisService().getClassLoader());

        TokenCallbackHandler tokenCallbackHandler = null;

        if (rpd != null) {
            tokenCallbackHandler = new TokenCallbackHandler(rmd.getTokenStorage(),
                    RampartUtil.getPasswordCB(rmd), rpd.getRampartConfig());
        } else {
            tokenCallbackHandler = new TokenCallbackHandler(rmd.getTokenStorage(),
                    RampartUtil.getPasswordCB(rmd));
        }

        if (rpd.isSymmetricBinding()) {
            // Here we have to create the CB handler to get the tokens from the
            // token storage
			log.debug("Processing security header using SymetricBinding");

			if (rpd.getSignatureToken() instanceof IssuedToken) {
				String tokenType = ((IssuedToken) rpd.getInitiatorToken()).getRstTokenType();
				if ("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
						.equals(tokenType.trim()) && !TrustUtil.isDoomParserPoolUsed()) {
                        DocumentBuilderFactoryImpl.setDOOMRequired(true);
                }
			}

            results = engine.processSecurityHeader(rmd.getDocument(), actorValue,
                    tokenCallbackHandler, signatureCrypto, RampartUtil.getEncryptionCrypto(
                            rpd.getRampartConfig(), msgCtx.getAxisService().getClassLoader()));

			if (rpd.getSignatureToken() instanceof IssuedToken) {
				String tokenType = ((IssuedToken) rpd.getInitiatorToken()).getRstTokenType();
				if ("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
						.equals(tokenType.trim()) && !TrustUtil.isDoomParserPoolUsed()){
                        DocumentBuilderFactoryImpl.setDOOMRequired(false);
                }
			}

            // Remove encryption tokens if this is the initiator and if initiator is receiving a
            // message

            if (rmd.isInitiator()
                    && (msgCtx.getFLOW() == MessageContext.IN_FLOW || msgCtx.getFLOW() == MessageContext.IN_FAULT_FLOW)) {
                tokenCallbackHandler.removeEncryptedToken();
            }

        } else {
            log.debug("Processing security header in normal path");
			if (rpd.getInitiatorToken() instanceof IssuedToken) {
				String tokenType = ((IssuedToken) rpd.getInitiatorToken()).getRstTokenType();
				if ("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
						.equals(tokenType.trim()) && !TrustUtil.isDoomParserPoolUsed()) {
                    	DocumentBuilderFactoryImpl.setDOOMRequired(true);
                }
			}

            if (rmd.isIncomingTTLCheck()) {
                results = engine.processSecurityHeader(rmd.getDocument(), actorValue,
                        tokenCallbackHandler, signatureCrypto, RampartUtil.getEncryptionCrypto(
                                rpd.getRampartConfig(), msgCtx.getAxisService().getClassLoader()), rmd.getTimeToLive());
            } else {
                results = engine.processSecurityHeader(rmd.getDocument(), actorValue,
                        tokenCallbackHandler, signatureCrypto, RampartUtil.getEncryptionCrypto(
                                rpd.getRampartConfig(), msgCtx.getAxisService().getClassLoader()));
            }

			if (rpd.getInitiatorToken() instanceof IssuedToken) {
				String tokenType = ((IssuedToken) rpd.getInitiatorToken()).getRstTokenType();
				if ("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
						.equals(tokenType.trim()) && !TrustUtil.isDoomParserPoolUsed()) {
                    	DocumentBuilderFactoryImpl.setDOOMRequired(false);
                }
			}
        }

        if (dotDebug) {
            t1 = System.currentTimeMillis();
        }

        // Store symm tokens
        // Pick the first SAML token
        // TODO : This is a hack , MUST FIX
        // get the sec context id from the req msg ctx

        // Store username in MessageContext property

        for (int j = 0; j < results.size(); j++) {
            WSSecurityEngineResult wser = (WSSecurityEngineResult) results.get(j);
            final Integer actInt = (Integer) wser.get(WSSecurityEngineResult.TAG_ACTION);
            if (WSConstants.ST_UNSIGNED == actInt.intValue()) {

                // If this is a SAML2.0 assertion
                if (wser.get(WSSecurityEngineResult.TAG_SAML_ASSERTION) instanceof Assertion) {
                    final Assertion assertion = (Assertion) wser
                            .get(WSSecurityEngineResult.TAG_SAML_ASSERTION);

                    Subject subject = assertion.getSubject();
                    if (subject != null && subject.getNameID() != null) {
                        msgCtx.setProperty(RampartConstants.SAML_SUBJECT_ID, subject.getNameID().getValue());
                    }

                    // if the subject confirmation method is Bearer, do not try to get the KeyInfo
                   if (TrustUtil.getSAML2SubjectConfirmationMethod(assertion).equals(
                            RahasConstants.SAML20_SUBJECT_CONFIRMATION_BEARER) ||
                        TrustUtil.getSAML2SubjectConfirmationMethod(assertion).equals(
                            RahasConstants.SAML20_SUBJECT_CONFIRMATION_SENDER_VOUCHES)) {
                        break;
                    }

                    String id = assertion.getID();

                    Date dateOfCreation = null;
                    Date dateOfExpiration = null;

                    // Read the validity period from the 'Conditions' element, else read it from SC
                    // Data
                    if (assertion.getConditions() != null) {
                        Conditions conditions = assertion.getConditions();
                        if (conditions.getNotBefore() != null) {
                            dateOfCreation = conditions.getNotBefore().toDate();
                        }
                        if (conditions.getNotOnOrAfter() != null) {
                            dateOfExpiration = conditions.getNotOnOrAfter().toDate();
                        }
                    } else {
                        SubjectConfirmationData scData = subject.getSubjectConfirmations().get(0)
                                .getSubjectConfirmationData();
                        if (scData.getNotBefore() != null) {
                            dateOfCreation = scData.getNotBefore().toDate();
                        }
                        if (scData.getNotOnOrAfter() != null) {
                            dateOfExpiration = scData.getNotOnOrAfter().toDate();
                        }
                    }

                    // TODO : SAML2KeyInfo element needs to be moved to WSS4J.
                    SAML2KeyInfo saml2KeyInfo = SAML2Utils.getSAML2KeyInfo(assertion,
                            signatureCrypto, tokenCallbackHandler);

                    // Store the token
                    try {
                        TokenStorage store = rmd.getTokenStorage();
                        if (store.getToken(id) == null) {
                            Token token = new Token(id,
                                    (OMElement) SAML2Utils.getElementFromAssertion(assertion),
                                    dateOfCreation, dateOfExpiration);
                            token.setSecret(saml2KeyInfo.getSecret());
                            store.add(token);
                        }
                    } catch (Exception e) {
                        throw new RampartException("errorInAddingTokenIntoStore", e);
                    }

                }
                // if this is a SAML1.1 assertion
                else {
//                    final SAMLAssertion assertion = ((SAMLAssertion) wser
//                            .get(WSSecurityEngineResult.TAG_SAML_ASSERTION));
//
//                    Iterator iterator = assertion.getStatements();
//                    while (iterator.hasNext()) {
//                        SAMLSubjectStatement samlSubjectStatement = (SAMLSubjectStatement) iterator.next();
//                        SAMLSubject samlSubject = samlSubjectStatement.getSubject();
//                        if (samlSubject != null && samlSubject.getNameIdentifier() != null) {
//                            msgCtx.setProperty(RampartConstants.SAML_SUBJECT_ID,
//                                               samlSubject.getNameIdentifier().getName());
//                        }
//                    }
//
//                    // if the subject confirmation method is Bearer, do not try to get the KeyInfo
//                    if (RahasConstants.SAML11_SUBJECT_CONFIRMATION_BEARER.equals(TrustUtil
//                                         .getSAML11SubjectConfirmationMethod(assertion)) ||
//                        RahasConstants.SAML11_SUBJECT_CONFIRMATION_SENDER_VOUCHES.equals(TrustUtil
//                                         .getSAML11SubjectConfirmationMethod(assertion))) {
//                        break;
//                    }
//
//                    String id = assertion.getId();
//                    Date created = assertion.getNotBefore();
//                    Date expires = assertion.getNotOnOrAfter();
//                    SAMLKeyInfo samlKi = SAMLUtil.getSAMLKeyInfo(assertion, signatureCrypto,
//                            tokenCallbackHandler);
//                    try {
//                        TokenStorage store = rmd.getTokenStorage();
//                        if (store.getToken(id) == null) {
//                            Token token = new Token(id, (OMElement) assertion.toDOM(), created,
//                                    expires);
//                            token.setSecret(samlKi.getSecret());
//                            store.add(token);
//                        }
//                    } catch (Exception e) {
//                        throw new RampartException("errorInAddingTokenIntoStore", e);
//                    }

                    log.error("SAML 1.1 is not supported");
                }
            } else if (WSConstants.UT == actInt.intValue()) {

                WSUsernameTokenPrincipal userNameTokenPrincipal = (WSUsernameTokenPrincipal) wser
                        .get(WSSecurityEngineResult.TAG_PRINCIPAL);

                String username = userNameTokenPrincipal.getName();
                msgCtx.setProperty(RampartMessageData.USERNAME, username);

                if (userNameTokenPrincipal.getNonce() != null) {
                    // Check whether this is a replay attack. To verify that we need to check
                    // whether nonce value
                    // is a repeating one
                    int nonceLifeTimeInSeconds = 0;

                    if (rpd.getRampartConfig() != null) {

                        String stringLifeTime = rpd.getRampartConfig().getNonceLifeTime();

                        try {
                            nonceLifeTimeInSeconds = Integer.parseInt(stringLifeTime);

                        } catch (NumberFormatException e) {
                            log.error(
                                    "Invalid value for nonceLifeTime in rampart configuration file.",
                                    e);
                            throw new RampartException("invalidNonceLifeTime", e);

                        }
                    }

                    String serviceEndpointName = msgCtx.getAxisService().getEndpointName();

                    boolean valueRepeating = serviceNonceCache.isNonceRepeatingForService(
                            serviceEndpointName, username, userNameTokenPrincipal.getNonce());

                    if (valueRepeating) {
                        throw new RampartException("repeatingNonceValue", new Object[] {
                                userNameTokenPrincipal.getNonce(), username });
                    }

                    serviceNonceCache.addNonceForService(serviceEndpointName, username,
                            userNameTokenPrincipal.getNonce(), nonceLifeTimeInSeconds);
                }
            } else if (WSConstants.SIGN == actInt.intValue()) {
                X509Certificate cert = (X509Certificate) wser.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);

				if (rpd.isAsymmetricBinding() && cert == null && rpd.getInitiatorToken() != null
						&& !(rpd.getInitiatorToken() instanceof IssuedToken)
						&& !rpd.getInitiatorToken().isDerivedKeys()) {
					// If symmetric binding is used, the certificate should
					// be null.If certificate is not null then probably initiator
					// and recipient are using 2 different bindings.
					throw new RampartException("invalidSignatureAlgo");
				}

                 msgCtx.setProperty(RampartMessageData.X509_CERT, cert);

            } else if (WSConstants.KERBEROS == actInt.intValue()) {
                KerberosTokenPrincipal principal = null;
                principal = ((KerberosTokenPrincipal) wser
                        .get(WSSecurityEngineResult.TAG_PRINCIPAL));
                if (principal != null) {
                    String clientPricipalName = principal.getClientPrincipalName();
                    String servicePricipalName = principal.getServicePrincipalName();
                    if (clientPricipalName != null) {
                        msgCtx.getOptions().setProperty(KerberosConfig.CLIENT_PRINCIPLE_NAME,
                                clientPricipalName);
                    }
                    if (servicePricipalName != null) {
                        msgCtx.getOptions().setProperty(KerberosConfig.SERVICE_PRINCIPLE_NAME,
                                servicePricipalName);
                    }
                }
            } else if (WSConstants.KERBEROS_ENCR == actInt.intValue()) {
                KerberosTokenPrincipal principal = null;
                principal = ((KerberosTokenPrincipal) wser
                        .get(WSSecurityEngineResult.TAG_PRINCIPAL));
                if (principal != null) {
                    String clientPricipalName = principal.getClientPrincipalName();
                    String servicePricipalName = principal.getServicePrincipalName();
                    if (clientPricipalName != null) {
                        msgCtx.getOptions().setProperty(KerberosConfig.CLIENT_PRINCIPLE_NAME,
                                clientPricipalName);
                    }
                    if (servicePricipalName != null) {
                        msgCtx.getOptions().setProperty(KerberosConfig.SERVICE_PRINCIPLE_NAME,
                                servicePricipalName);
                    }
                }
            } else if (WSConstants.KERBEROS_SIGN == actInt.intValue()) {
                KerberosTokenPrincipal principal = null;
                principal = ((KerberosTokenPrincipal) wser
                        .get(WSSecurityEngineResult.TAG_PRINCIPAL));
                if (principal != null) {
                    String clientPricipalName = principal.getClientPrincipalName();
                    String servicePricipalName = principal.getServicePrincipalName();
                    if (clientPricipalName != null) {
                        msgCtx.getOptions().setProperty(KerberosConfig.CLIENT_PRINCIPLE_NAME,
                                clientPricipalName);
                    }
                    if (servicePricipalName != null) {
                        msgCtx.getOptions().setProperty(KerberosConfig.SERVICE_PRINCIPLE_NAME,
                                servicePricipalName);
                    }
                }
            }

        }
        RampartConfig rampartConfig = rpd.getRampartConfig();
        if (rampartConfig != null && !rampartConfig.isOptimizeMessageProcessingForTransportBinding()) {
            //Convert back to llom since the inflow cannot use DOOM
            SOAPEnvelope env = Axis2Util.getSOAPEnvelopeFromDOMDocument(rmd.getDocument(), true);
            msgCtx.setEnvelope(env);
        }

        if (dotDebug) {
            t2 = System.currentTimeMillis();
        }

        // Convert back to llom since the inflow cannot use DOOM
        Axis2Util.useDOOM(false);

        PolicyValidatorCallbackHandler validator = RampartUtil.getPolicyValidatorCB(msgCtx, rpd);

        validator.validate(data, results);

        if (dotDebug) {
            t3 = System.currentTimeMillis();
            tlog.debug("processHeader by WSSecurityEngine took : " + (t1 - t0)
                    + ", DOOM conversion took :" + (t2 - t1)
                    + ", PolicyBasedResultsValidattor took " + (t3 - t2));
        }

        log.debug("Return process(MessageContext msgCtx)");
        return results;
    }

    /**
     * This method is used to verify SOAP Header element to avoid XML Signature Wrapping attack. This method checks
     * whether there is a Body element inside the Header element when the body content is signed.
     *
     * @param element SOAP element to be verified
     * @return Whether the header element is contained with a Body element
     */
    private boolean isValidHeaderForSignedBody(OMElement element) {
        if (null != element && element.getLocalName().equals(WSConstants.ELEM_BODY)) {
            return false;

        } else if (null != element) {
            Iterator children = element.getChildren();
            if (null != children) {
                while (children.hasNext()) {
                    Object child = children.next();
                    if (child instanceof OMElement && !((OMElement) child).getLocalName().equals(WSConstants.WSSE_LN)
                            && !isValidHeaderForSignedBody((OMElement) child)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    // Check whether this a soap fault because of failure in processing the security header
    // and if so, we don't expect the security header
    //
    //

    private boolean isSecurityFault(RampartMessageData rmd) {

        SOAPEnvelope soapEnvelope = rmd.getMsgContext().getEnvelope();
        SOAPFault soapFault = soapEnvelope.getBody().getFault();

        // This is not a soap fault
        if (soapFault == null) {
            return false;
        }

        String soapVersionURI = rmd.getMsgContext().getEnvelope().getNamespace().getNamespaceURI();
        SOAPFaultCode faultCode = soapFault.getCode();
        if (faultCode == null) {
            // If no fault code is given, then it can't be security fault
            return false;
        }

        if (soapVersionURI.equals(SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI)) {
            // This is a fault processing the security header
            if (faultCode.getTextAsQName().getNamespaceURI().equals(WSConstants.WSSE_NS)) {
                return true;
            }
        } else if (soapVersionURI.equals(SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI)) {
            // TODO AXIOM API returns only one fault sub code, there can be many
            SOAPFaultSubCode faultSubCode = faultCode.getSubCode();
            if (faultSubCode != null) {
                SOAPFaultValue faultSubCodeValue = faultSubCode.getValue();

                // This is a fault processing the security header
                if (faultSubCodeValue != null
                        && faultSubCodeValue.getTextAsQName().getNamespaceURI()
                                .equals(WSConstants.WSSE_NS)) {
                    return true;
                }
            }
        }

        return false;
    }
}
