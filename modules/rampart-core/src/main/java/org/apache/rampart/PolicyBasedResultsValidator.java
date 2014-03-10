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

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.axiom.om.OMNamespace;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.SupportingPolicyData;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.*;
import org.apache.ws.security.*;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.jaxen.XPath;
import org.jaxen.JaxenException;

import javax.xml.namespace.QName;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.*;

public class PolicyBasedResultsValidator implements PolicyValidatorCallbackHandler {

    private static Log log = LogFactory.getLog(PolicyBasedResultsValidator.class);

    /**
     * {@inheritDoc}
     */
    public void validate(ValidatorData data, Vector results) throws RampartException {

        RampartMessageData rmd = data.getRampartMessageData();

        RampartPolicyData rpd = rmd.getPolicyData();

        Set namespaces = RampartUtil.findAllPrefixNamespaces(rmd.getMsgContext().getEnvelope(),
                rpd.getDeclaredNamespaces());

        rmd.setDeclaredNamespaces(namespaces);

        // If there's Security policy present and no results
        // then we should throw an error
        if (rpd != null && results == null) {
            throw new RampartException("noSecurityResults");
        }

        // Check presence of timestamp
        WSSecurityEngineResult tsResult = null;
        if (rpd != null && rpd.isIncludeTimestamp()) {
            tsResult = WSSecurityUtil.fetchActionResult(results, WSConstants.TS);
            if (tsResult == null && !rpd.isIncludeTimestampOptional()) {
                throw new RampartException("timestampMissing");
            }

        }

        WSSecurityEngineResult krbResult;
        krbResult = WSSecurityUtil.fetchActionResult(results, WSConstants.KERBEROS_SIGN);
        if (krbResult == null) {
            krbResult = WSSecurityUtil.fetchActionResult(results, WSConstants.KERBEROS_ENCR);
        }
        if (krbResult == null) {
            krbResult = WSSecurityUtil.fetchActionResult(results, WSConstants.KERBEROS);
        }
        if (krbResult != null) {
            // TODO
            return;
        }

        Vector encryptedParts = new Vector();
        Vector signatureParts = new Vector();

        if (!rpd.getRampartConfig().isOptimizeMessageProcessingForTransportBinding()) {
            //sig/encr
            encryptedParts = RampartUtil.getEncryptedParts(rmd);
            if (rpd != null && rpd.isSignatureProtection() && isSignatureRequired(rmd)) {

                String sigId = RampartUtil.getSigElementId(rmd);

                encryptedParts.add(new WSEncryptionPart(WSConstants.SIG_LN,
                        WSConstants.SIG_NS, "Element"));
            }

            signatureParts = RampartUtil.getSignedParts(rmd);

            //Timestamp is not included in sig parts
            if (tsResult != null || !rpd.isIncludeTimestampOptional()) {
                if (rpd != null && rpd.isIncludeTimestamp()
                        && !rpd.isTransportBinding()) {
                    signatureParts.add(new WSEncryptionPart("timestamp"));
                }
            }
        }

        if (!rmd.isInitiator()) {

            // Just an indicator for EndorsingSupportingToken signature
            SupportingToken endSupportingToken = rpd.getEndorsingSupportingTokens();
            if (endSupportingToken != null && !endSupportingToken.isOptional()) {
                SignedEncryptedParts endSignedParts = endSupportingToken.getSignedParts();
                if ((endSignedParts != null && !endSignedParts.isOptional() && (endSignedParts
                        .isBody() || endSignedParts.getHeaders().size() > 0))
                        || rpd.isIncludeTimestamp()) {
                    signatureParts.add(new WSEncryptionPart("EndorsingSupportingTokens"));
                }
            }
            // Just an indicator for SignedEndorsingSupportingToken signature
            SupportingToken sgndEndSupportingToken = rpd.getSignedEndorsingSupportingTokens();
            if (sgndEndSupportingToken != null && !sgndEndSupportingToken.isOptional()) {
                SignedEncryptedParts sgndEndSignedParts = sgndEndSupportingToken.getSignedParts();
                if ((sgndEndSignedParts != null && !sgndEndSignedParts.isOptional() && (sgndEndSignedParts
                        .isBody() || sgndEndSignedParts.getHeaders().size() > 0))
                        || rpd.isIncludeTimestamp()) {
                    signatureParts.add(new WSEncryptionPart("SignedEndorsingSupportingTokens"));
                }
            }

            Vector supportingToks = rpd.getSupportingTokensList();
            for (int i = 0; i < supportingToks.size(); i++) {
                SupportingToken supportingToken = (SupportingToken) supportingToks.get(i);
                if (supportingToken != null && !supportingToken.isOptional()) {
                    SupportingPolicyData policyData = new SupportingPolicyData();
                    policyData.build(supportingToken);
                    encryptedParts.addAll(RampartUtil.getSupportingEncryptedParts(rmd, policyData));
                    signatureParts.addAll(RampartUtil.getSupportingSignedParts(rmd, policyData));
                }
            }
        }

        if (!rpd.getRampartConfig().isOptimizeMessageProcessingForTransportBinding()) {
            validateEncrSig(data, encryptedParts, signatureParts, results);
        }

        if (!rpd.isTransportBinding()) {
            validateProtectionOrder(data, results);
        }

        if (!rpd.getRampartConfig().isOptimizeMessageProcessingForTransportBinding()) {
            validateEncryptedParts(data, encryptedParts, results, namespaces);

            validateSignedPartsHeaders(data, signatureParts, results);
        }

        validateRequiredElements(data, namespaces);

        // Supporting tokens
        if (!rmd.isInitiator()) {
            validateSupportingTokens(data, results);
        }

        /*
         * Now we can check the certificate used to sign the message. In the following
         * implementation the certificate is only trusted if either it itself or the certificate of
         * the issuer is installed in the keystore.
         * 
         * Note: the method verifyTrust(X509Certificate) allows custom implementations with other
         * validation algorithms for subclasses.
         */

        // Extract the signature action result from the action vector
        WSSecurityEngineResult actionResult = WSSecurityUtil.fetchActionResult(results,
                WSConstants.SIGN);

        if (actionResult != null) {
            X509Certificate returnCert = (X509Certificate) actionResult
                    .get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);

            if (returnCert != null) {
                if (!verifyTrust(returnCert, rmd)) {
                    throw new RampartException("trustVerificationError");
                }
            }
        }

        /*
         * Perform further checks on the timestamp that was transmitted in the header. In the
         * following implementation the timestamp is valid if : Timestamp->Created < 'now' <
         * Timestamp->Created < 'now' < Timestamp->Expires.
         * (Last test handled by WSS4J also if timeStampStrict enabled)
         * 
         * Note: the method verifyTimestamp(Timestamp) allows custom implementations with other
         * validation algorithms for subclasses.
         */

        // Extract the timestamp action result from the action vector
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.TS);

        if (actionResult != null) {
            Timestamp timestamp = (Timestamp) actionResult
                    .get(WSSecurityEngineResult.TAG_TIMESTAMP);

            if (timestamp != null) {
                if (!verifyTimestamp(timestamp, rmd)) {
                    throw new RampartException("cannotValidateTimestamp");
                }
            }
        }

        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SAML_TIMESTAMP);
        if (actionResult != null) {
            Timestamp timestamp = (Timestamp) actionResult
                    .get(WSSecurityEngineResult.TAG_TIMESTAMP);

            if (timestamp != null) {
                if (!verifySAMLTokenTimestamp(timestamp, rmd)) {
                    throw new RampartException("invalidTimeStampInSamlToken");
                }
            }
        }
    }

    /**
     * @param encryptedParts
     * @param signatureParts
     */
    protected void validateEncrSig(ValidatorData data, Vector encryptedParts,
                                   Vector signatureParts, Vector results) throws RampartException {
        ArrayList actions = getSigEncrActions(results);
        boolean sig = false;
        boolean encr = false;
        for (Iterator iter = actions.iterator(); iter.hasNext(); ) {
            Integer act = (Integer) iter.next();
            if (act.intValue() == WSConstants.SIGN) {
                sig = true;
            } else if (act.intValue() == WSConstants.ENCR) {
                encr = true;
            }
        }

        RampartPolicyData rpd = data.getRampartMessageData().getPolicyData();

        SupportingToken sgndSupTokens = rpd.getSignedSupportingTokens();
        SupportingToken sgndEndorSupTokens = rpd.getSignedEndorsingSupportingTokens();

        if (sig && signatureParts.size() == 0
                && (sgndSupTokens == null || sgndSupTokens.getTokens().size() == 0)
                && (sgndEndorSupTokens == null || sgndEndorSupTokens.getTokens().size() == 0)) {

            // Unexpected signature
            throw new RampartException("unexprectedSignature");
        } else if (!sig && signatureParts.size() > 0) {

            // required signature missing
            throw new RampartException("signatureMissing");
        }

        if (encr && encryptedParts.size() == 0) {

            // Check whether its just an encrypted key
            ArrayList list = this.getResults(results, WSConstants.ENCR);
            boolean encrDataFound = false;
            for (Iterator iter = list.iterator(); iter.hasNext(); ) {
                WSSecurityEngineResult result = (WSSecurityEngineResult) iter.next();
                ArrayList dataRefURIs = (ArrayList) result
                        .get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                if (dataRefURIs != null && dataRefURIs.size() != 0) {
                    encrDataFound = true;
                }
            }
            // TODO check whether the encrptedDataFound is an UsernameToken
            if (encrDataFound && !isUsernameTokenPresent(data)) {
                // Unexpected encryption
                throw new RampartException("unexprectedEncryptedPart");
            }
        } else if (!encr && encryptedParts.size() > 0) {

            // required signature missing
            throw new RampartException("encryptionMissing");
        }
    }

    /**
     * @param data
     * @param results
     */
    protected void validateSupportingTokens(ValidatorData data, Vector results)
            throws RampartException {

        // Check for UsernameToken
        RampartPolicyData rpd = data.getRampartMessageData().getPolicyData();
        Vector supportingToks = rpd.getSupportingTokensList();
        for (int i = 0; i < supportingToks.size(); i++) {
            SupportingToken suppTok = (SupportingToken) supportingToks.get(i);
            handleSupportingTokens(results, suppTok);
        }
        SupportingToken signedSuppToken = rpd.getSignedSupportingTokens();
        handleSupportingTokens(results, signedSuppToken);
        SupportingToken signedEndSuppToken = rpd.getSignedEndorsingSupportingTokens();
        handleSupportingTokens(results, signedEndSuppToken);
        SupportingToken endSuppToken = rpd.getEndorsingSupportingTokens();
        handleSupportingTokens(results, endSuppToken);
    }

    /**
     * @param results
     * @param suppTok
     * @throws RampartException
     */
    protected void handleSupportingTokens(Vector results, SupportingToken suppTok)
            throws RampartException {

        if (suppTok == null) {
            return;
        }

        ArrayList tokens = suppTok.getTokens();
        for (Iterator iter = tokens.iterator(); iter.hasNext(); ) {
            Token token = (Token) iter.next();
            if (token instanceof UsernameToken) {
                UsernameToken ut = (UsernameToken) token;
                // Check presence of a UsernameToken
                WSSecurityEngineResult utResult = WSSecurityUtil.fetchActionResult(results,
                        WSConstants.UT);
                if (utResult == null && !ut.isOptional()) {
                    throw new RampartException("usernameTokenMissing");
                }

            } else if (token instanceof IssuedToken) {
                //TODO is is enough to check for ST_UNSIGNED results ??
                WSSecurityEngineResult samlResult = WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
                if (samlResult == null) {
                    throw new RampartException("samlTokenMissing");
                }

                IssuedToken issuedToken = (IssuedToken) token;

                if (issuedToken.getRstTokenType() != null) {

                    // check the token type
                    String tokenType = (String) samlResult.get(WSConstants.SAML_VERSION);
                    if (tokenType == null) {
                        throw new RampartException("samlversionmismatch");
                    }

                    if (!issuedToken.getRstTokenType().trim().equals(tokenType.trim())) {
                        if (log.isDebugEnabled()) {
                            log.debug("The issued token should contain a SAML token with the version "
                                    + issuedToken.getRstTokenType());
                        }
                        throw new RampartException("samlversionmismatch");
                    }
                }

                //verify the mandatory claims
                Set claimsAvailable = (Set) samlResult.get(WSConstants.SAML_CLAIM_SET);
                if (issuedToken.getRstClaimSet().size() > 0) {
                    for (String claimUri : issuedToken.getRstClaimSet()) {
                        if (!claimsAvailable.contains(claimUri)) {
                            if (log.isDebugEnabled()) {
                                log.debug("Issued token does not contain the claim : " + claimUri);
                            }
                            throw new RampartException("requiredClaimMissing");
                        }
                    }
                }
            } else if (token instanceof X509Token) {
                X509Token x509Token = (X509Token) token;
                WSSecurityEngineResult x509Result = WSSecurityUtil.fetchActionResult(results,
                        WSConstants.BST);
                if (x509Result == null && !x509Token.isOptional()) {
                    throw new RampartException("binaryTokenMissing");
                }
            }
        }
    }

    /**
     * @param data
     * @param results
     */
    protected void validateProtectionOrder(ValidatorData data, Vector results)
            throws RampartException {

        String protectionOrder = data.getRampartMessageData().getPolicyData().getProtectionOrder();
        ArrayList sigEncrActions = this.getSigEncrActions(results);

        if (sigEncrActions.size() < 2) {
            // There are no results to COMPARE
            return;
        }

        boolean sigNotPresent = true;
        boolean encrNotPresent = true;

        for (Iterator iter = sigEncrActions.iterator(); iter.hasNext(); ) {
            Integer act = (Integer) iter.next();
            if (act.intValue() == WSConstants.SIGN) {
                sigNotPresent = false;
            } else if (act.intValue() == WSConstants.ENCR) {
                encrNotPresent = false;
            }
        }

        // Only one action is present, so there is no order to check
        if (sigNotPresent || encrNotPresent) {
            return;
        }

        boolean done = false;
        if (SPConstants.SIGN_BEFORE_ENCRYPTING.equals(protectionOrder)) {

            boolean sigFound = false;
            for (Iterator iter = sigEncrActions.iterator(); iter.hasNext() || !done; ) {
                Integer act = (Integer) iter.next();
                if (act.intValue() == WSConstants.ENCR && !sigFound) {
                    // We found ENCR and SIGN has not been found - break and fail
                    break;
                }
                if (act.intValue() == WSConstants.SIGN) {
                    sigFound = true;
                } else if (sigFound) {
                    // We have an ENCR action after sig
                    done = true;
                }
            }

        } else {
            boolean encrFound = false;
            for (Iterator iter = sigEncrActions.iterator(); iter.hasNext(); ) {
                Integer act = (Integer) iter.next();
                if (act.intValue() == WSConstants.SIGN && !encrFound) {
                    // We found SIGN and ENCR has not been found - break and fail
                    break;
                }
                if (act.intValue() == WSConstants.ENCR) {
                    encrFound = true;
                } else if (encrFound) {
                    // We have an ENCR action after sig
                    done = true;
                }
            }
        }

        if (!done) {
            throw new RampartException("protectionOrderMismatch");
        }
    }

    protected ArrayList getSigEncrActions(Vector results) {
        ArrayList sigEncrActions = new ArrayList();
        for (Iterator iter = results.iterator(); iter.hasNext(); ) {
            Integer actInt = (Integer) ((WSSecurityEngineResult) iter.next())
                    .get(WSSecurityEngineResult.TAG_ACTION);
            int action = actInt.intValue();
            if (WSConstants.SIGN == action || WSConstants.ENCR == action) {
                sigEncrActions.add(Integer.valueOf(action));
            }

        }
        return sigEncrActions;
    }

    protected void validateEncryptedParts(ValidatorData data, Vector encryptedParts,
                                          Vector results, Set namespaces)
            throws RampartException {

        RampartMessageData rmd = data.getRampartMessageData();

        ArrayList encrRefs = getEncryptedReferences(results);

        RampartPolicyData rpd = rmd.getPolicyData();

        // build the list of encrypted nodes based on the dataRefs xpath expressions
        SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();

        Map decryptedElements = new HashMap();
        for (int i = 0; i < encrRefs.size(); i++) {
            WSDataRef dataRef = (WSDataRef) encrRefs.get(i);

            if (dataRef == null || dataRef.getXpath() == null) {
                continue;
            }

            try {
                XPath xp = new AXIOMXPath(dataRef.getXpath());

                Iterator nsIter = namespaces.iterator();

                while (nsIter.hasNext()) {
                    OMNamespace tmpNs = (OMNamespace) nsIter.next();
                    xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
                }

                Iterator nodesIterator = xp.selectNodes(envelope).iterator();

                while (nodesIterator.hasNext()) {
                    decryptedElements.put(nodesIterator.next(),
                            Boolean.valueOf(dataRef.isContent()));
                }

            } catch (JaxenException e) {
                // This has to be changed to propagate an instance of a RampartException up
                throw new RampartException(
                        "An error occurred while searching for decrypted elements.", e);
            }

        }

        boolean isBodyEncrypted = false;

        for (int i = 0; i < encryptedParts.size(); i++) {

            WSEncryptionPart encPart = (WSEncryptionPart) encryptedParts.get(i);

            // This is the encrypted Body and we already checked encrypted body
            if (encPart.getType() == WSConstants.PART_TYPE_BODY) {
                isBodyEncrypted = true;
                continue;
            }

            if ((WSConstants.SIG_LN.equals(encPart.getName()) && WSConstants.SIG_NS.equals(encPart
                    .getNamespace())) || encPart.getType() == WSConstants.PART_TYPE_HEADER) {
                if (!isRefIdPresent(encrRefs, new QName(encPart.getNamespace(), encPart.getName()))) {
                    throw new RampartException("encryptedPartMissing",
                            new String[]{encPart.getNamespace() + ":" + encPart.getName()});
                }
                continue;
            }

            // it is not a header or body part... verify encrypted xpath elements
            String xpath = encPart.getXpath();
            boolean found = false;
            try {
                XPath xp = new AXIOMXPath(xpath);
                Iterator nsIter = namespaces.iterator();

                while (nsIter.hasNext()) {
                    OMNamespace tmpNs = (OMNamespace) nsIter.next();
                    xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
                }

                Iterator nodesIterator = xp.selectNodes(envelope).iterator();

                while (nodesIterator.hasNext()) {
                    Object result = decryptedElements.get(nodesIterator.next());
                    if (result != null
                            && ("Element".equals(encPart.getEncModifier()) ^ ((Boolean) result)
                            .booleanValue())) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    throw new RampartException("encryptedPartMissing", new String[]{xpath});
                }

            } catch (JaxenException e) {
                // This has to be changed to propagate an instance of a RampartException up
                throw new RampartException(
                        "An error occurred while searching for decrypted elements.", e);
            }

        }

        //Check for encrypted body
        if (rpd.isEncryptBody() && !rpd.isEncryptBodyOptional()) {
            if (!isBodyEncrypted) {
                throw new RampartException("encryptedPartMissing",
                        new String[]{data.getBodyEncrDataId()});
            }
        }
    }

    public void validateRequiredElements(ValidatorData data, Set namespaces) throws RampartException {

        RampartMessageData rmd = data.getRampartMessageData();

        RampartPolicyData rpd = rmd.getPolicyData();

        SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();

        Iterator elementsIter = rpd.getRequiredElements().iterator();

        while (elementsIter.hasNext()) {

            String expression = (String) elementsIter.next();

            if ( !RampartUtil.checkRequiredElements(envelope, namespaces, expression)) {
                throw new RampartException("requiredElementsMissing", new String[]{expression});
            }
        }

    }

    protected void validateSignedPartsHeaders(ValidatorData data, Vector signatureParts,
                                              Vector results) throws RampartException {

        RampartMessageData rmd = data.getRampartMessageData();

        Node envelope = rmd.getDocument().getFirstChild();

        WSSecurityEngineResult[] actionResults = fetchActionResults(results, WSConstants.SIGN);

        // Find elements that are signed
        Vector actuallySigned = new Vector();
        if (actionResults != null) {
            for (int j = 0; j < actionResults.length; j++) {

                WSSecurityEngineResult actionResult = actionResults[j];
                List wsDataRefs = (List) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

                // if header was encrypted before it was signed, protected
                // element is 'EncryptedHeader.' the actual element is
                // first child element

                for (Iterator k = wsDataRefs.iterator(); k.hasNext(); ) {
                    WSDataRef wsDataRef = (WSDataRef) k.next();
                    Element protectedElement = wsDataRef.getProtectedElement();
                    if (protectedElement.getLocalName().equals("EncryptedHeader")) {
                        NodeList nodeList = protectedElement.getChildNodes();
                        for (int x = 0; x < nodeList.getLength(); x++) {
                            if (nodeList.item(x).getNodeType() == Node.ELEMENT_NODE) {
                                String ns = ((Element) nodeList.item(x)).getNamespaceURI();
                                String ln = ((Element) nodeList.item(x)).getLocalName();
                                actuallySigned.add(new QName(ns, ln));
                                break;
                            }
                        }
                    } else {
                        String ns = protectedElement.getNamespaceURI();
                        String ln = protectedElement.getLocalName();
                        actuallySigned.add(new QName(ns, ln));
                    }
                }

            }
        }

        for (int i = 0; i < signatureParts.size(); i++) {
            WSEncryptionPart wsep = (WSEncryptionPart) signatureParts.get(i);

            if (wsep.getType() == WSConstants.PART_TYPE_BODY) {

                QName bodyQName;

                if (WSConstants.URI_SOAP11_ENV.equals(envelope.getNamespaceURI())) {
                    bodyQName = new SOAP11Constants().getBodyQName();
                } else {
                    bodyQName = new SOAP12Constants().getBodyQName();
                }

                if (!actuallySigned.contains(bodyQName)
                        && !rmd.getPolicyData().isSignBodyOptional()) {
                    // soap body is not signed
                    throw new RampartException("bodyNotSigned");
                }

            } else if (wsep.getType() == WSConstants.PART_TYPE_HEADER
                    || wsep.getType() == WSConstants.PART_TYPE_ELEMENT) {

                Element element = (Element) WSSecurityUtil.findElement(envelope, wsep.getName(),
                        wsep.getNamespace());

                if (element == null) {
                    // The signedpart header or element we are checking is not present in
                    // soap envelope - this is allowed
                    continue;
                }

                // header or the element present in soap envelope - verify that it is part of
                // signature
                if (actuallySigned.contains(new QName(element.getNamespaceURI(), element
                        .getLocalName()))) {
                    continue;
                }

                String msg = wsep.getType() == WSConstants.PART_TYPE_HEADER ? "signedPartHeaderNotSigned"
                        : "signedElementNotSigned";

                // header or the element defined in policy is present but not signed
                throw new RampartException(msg, new String[]{wsep.getNamespace() + ":"
                        + wsep.getName()});

            }
        }
    }

    protected boolean isSignatureRequired(RampartMessageData rmd) {
        RampartPolicyData rpd = rmd.getPolicyData();
        return (rpd.isSymmetricBinding() && rpd.getSignatureToken() != null)
                || (!rpd.isSymmetricBinding() && !rpd.isTransportBinding() && ((rpd
                .getInitiatorToken() != null && rmd.isInitiator()) || rpd
                .getRecipientToken() != null && !rmd.isInitiator()));
    }

    /*
     * Verify whether timestamp of the message is valid.
     * If timeStampStrict is enabled in rampartConfig; testing of timestamp has not expired
     * ('now' is before ts->Expires) is also handled earlier by WSS4J without timeskew.
      */
    protected boolean verifyTimestamp(Timestamp timestamp, RampartMessageData rmd)
            throws RampartException {

        // adjust 'now' with allowed timeskew
        long maxSkew = RampartUtil.getTimestampMaxSkew(rmd);

        //Verify that ts->Created is before 'now'

        Calendar cre = timestamp.getCreated();
        if (cre != null) {
            long now = Calendar.getInstance().getTimeInMillis();

            //calculate the tolerance limit for timeskew of the 'Created' in timestamp
            if (maxSkew > 0) {
                now += (maxSkew * 1000);
            }

            // fail if ts->Created is after 'now'
            if (cre.getTimeInMillis() > now) {
                return false;
            }
        }

        Calendar expires = timestamp.getExpires();

        if (expires != null) {

            long now = Calendar.getInstance().getTimeInMillis();
            //calculate the tolerance limit for timeskew of the 'Expires' in timestamp
            if (maxSkew > 0) {
                now -= (maxSkew * 1000);
            }
            //fail if ts->Expires is before 'now'
            if (expires.getTimeInMillis() < now) {
                return false;
            }
        }


        return true;
    }

    /**
     * Evaluate whether a given certificate should be trusted. Hook to allow subclasses to implement
     * custom validation methods however they see fit.
     * <p/>
     * Policy used in this implementation: 1. Search the keystore for the transmitted certificate 2.
     * Search the keystore for a connection to the transmitted certificate (that is, search for
     * certificate(s) of the issuer of the transmitted certificate 3. Verify the trust path for
     * those certificates found because the search for the issuer might be fooled by a phony DN
     * (String!)
     *
     * @param cert the certificate that should be validated against the keystore
     * @return true if the certificate is trusted, false if not (AxisFault is thrown for exceptions
     *         during CertPathValidation)
     * @throws WSSecurityException
     */
    protected boolean verifyTrust(X509Certificate cert, RampartMessageData rmd)
            throws RampartException {

        // If no certificate was transmitted, do not trust the signature
        if (cert == null) {
            return false;
        }

        String[] aliases = null;
        String alias = null;
        X509Certificate[] certs;

        String subjectString = cert.getSubjectDN().getName();
        String issuerString = cert.getIssuerDN().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        boolean doDebug = log.isDebugEnabled();

        if (doDebug) {
            log.debug("WSHandler: Transmitted certificate has subject " + subjectString);
            log.debug("WSHandler: Transmitted certificate has issuer " + issuerString + " (serial "
                    + issuerSerial + ")");
        }

        // FIRST step
        // Search the keystore for the transmitted certificate

        // Search the keystore for the alias of the transmitted certificate
        try {
            alias = RampartUtil.getSignatureCrypto(rmd.getPolicyData().getRampartConfig(),
                    rmd.getCustomClassLoader()).getAliasForX509Cert(issuerString, issuerSerial);
        } catch (WSSecurityException ex) {
            throw new RampartException("cannotFindAliasForCert", new String[]{subjectString}, ex);
        }

        if (alias != null) {
            // Retrieve the certificate for the alias from the keystore
            try {
                certs = RampartUtil.getSignatureCrypto(rmd.getPolicyData().getRampartConfig(),
                        rmd.getCustomClassLoader()).getCertificates(alias);
            } catch (WSSecurityException ex) {
                throw new RampartException("noCertForAlias", new String[]{alias}, ex);
            }

            // If certificates have been found, the certificates must be compared
            // to ensure against phony DNs (compare encoded form including signature)
            if (certs != null && certs.length > 0 && cert.equals(certs[0])) {
                if (doDebug) {
                    log.debug("Direct trust for certificate with " + subjectString);
                }
                // Set the alias of the cert used for the msg. sig. as a msg. cxt. property
                rmd.getMsgContext().setProperty(RampartMessageData.SIGNATURE_CERT_ALIAS, alias);
                return true;
            }
        } else {
            if (doDebug) {
                log.debug("No alias found for subject from issuer with " + issuerString
                        + " (serial " + issuerSerial + ")");
            }
        }

        // SECOND step
        // Search for the issuer of the transmitted certificate in the keystore

        // Search the keystore for the alias of the transmitted certificates issuer
        try {
            aliases = RampartUtil.getSignatureCrypto(rmd.getPolicyData().getRampartConfig(),
                    rmd.getCustomClassLoader()).getAliasesForDN(issuerString);
        } catch (WSSecurityException ex) {
            throw new RampartException("cannotFindAliasForCert", new String[]{issuerString}, ex);
        }

        // If the alias has not been found, the issuer is not in the keystore
        // As a direct result, do not trust the transmitted certificate
        if (aliases == null || aliases.length < 1) {
            if (doDebug) {
                log.debug("No aliases found in keystore for issuer " + issuerString
                        + " of certificate for " + subjectString);
            }
            return false;
        }

        // THIRD step
        // Check the certificate trust path for every alias of the issuer found in the keystore
        for (int i = 0; i < aliases.length; i++) {
            alias = aliases[i];

            if (doDebug) {
                log.debug("Preparing to validate certificate path with alias " + alias
                        + " for issuer " + issuerString);
            }

            // Retrieve the certificate(s) for the alias from the keystore
            try {
                certs = RampartUtil.getSignatureCrypto(rmd.getPolicyData().getRampartConfig(),
                        rmd.getCustomClassLoader()).getCertificates(alias);
            } catch (WSSecurityException ex) {
                throw new RampartException("noCertForAlias", new String[]{alias}, ex);
            }

            // If no certificates have been found, there has to be an error:
            // The keystore can find an alias but no certificate(s)
            if (certs == null || certs.length < 1) {
                throw new RampartException("noCertForAlias", new String[]{alias});
            }

            // Form a certificate chain from the transmitted certificate
            // and the certificate(s) of the issuer from the keystore
            // First, create new array
            X509Certificate[] x509certs = new X509Certificate[certs.length + 1];
            // Then add the first certificate ...
            x509certs[0] = cert;
            // ... and the other certificates
            for (int j = 0; j < certs.length; j++) {
                cert = certs[j];
                x509certs[j + 1] = cert;
            }
            certs = x509certs;

            // Use the validation method from the crypto to check whether the subjects certificate
            // was really signed by the issuer stated in the certificate
            try {
                if (RampartUtil.getSignatureCrypto(rmd.getPolicyData().getRampartConfig(),
                        rmd.getCustomClassLoader()).validateCertPath(certs)) {
                    if (doDebug) {
                        log.debug("WSHandler: Certificate path has been verified for certificate with subject "
                                + subjectString);
                    }
                    return true;
                }
            } catch (WSSecurityException ex) {
                throw new RampartException("certPathVerificationFailed",
                        new String[]{subjectString}, ex);
            }
        }

        if (doDebug) {
            log.debug("WSHandler: Certificate path could not be verified for certificate with subject "
                    + subjectString);
        }
        return false;
    }

    protected ArrayList getEncryptedReferences(Vector results) {

        // there can be multiple ref lists
        ArrayList encrResults = getResults(results, WSConstants.ENCR);

        ArrayList refs = new ArrayList();

        for (Iterator iter = encrResults.iterator(); iter.hasNext(); ) {
            WSSecurityEngineResult engineResult = (WSSecurityEngineResult) iter.next();
            ArrayList dataRefUris = (ArrayList) engineResult
                    .get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

            // take only the ref list processing results
            if (dataRefUris != null) {
                for (Iterator iterator = dataRefUris.iterator(); iterator.hasNext(); ) {
                    WSDataRef uri = (WSDataRef) iterator.next();
                    refs.add(uri);
                }
            }
        }

        return refs;
    }

    protected ArrayList getResults(Vector results, int action) {

        ArrayList list = new ArrayList();

        for (int i = 0; i < results.size(); i++) {
            // Check the result of every action whether it matches the given
            // action
            Integer actInt = (Integer) ((WSSecurityEngineResult) results.get(i))
                    .get(WSSecurityEngineResult.TAG_ACTION);
            if (actInt.intValue() == action) {
                list.add((WSSecurityEngineResult) results.get(i));
            }
        }

        return list;
    }

    protected boolean isUsernameTokenPresent(ValidatorData data) {

        // TODO This can be integrated with supporting token processing
        // which also checks whether Username Tokens present

        RampartPolicyData rpd = data.getRampartMessageData().getPolicyData();

        Vector supportingToks = rpd.getSupportingTokensList();
        for (int i = 0; i < supportingToks.size(); i++) {
            SupportingToken suppTok = (SupportingToken) supportingToks.get(i);
            if (isUsernameTokenPresent(suppTok)) {
                return true;
            }
        }

        SupportingToken signedSuppToken = rpd.getSignedSupportingTokens();
        if (isUsernameTokenPresent(signedSuppToken)) {
            return true;
        }

        SupportingToken signedEndSuppToken = rpd.getSignedEndorsingSupportingTokens();
        if (isUsernameTokenPresent(signedEndSuppToken)) {
            return true;
        }

        SupportingToken endSuppToken = rpd.getEndorsingSupportingTokens();
        if (isUsernameTokenPresent(endSuppToken)) {
            return true;
        }

        return false;

    }

    protected boolean isUsernameTokenPresent(SupportingToken suppTok) {

        if (suppTok == null) {
            return false;
        }

        ArrayList tokens = suppTok.getTokens();
        for (Iterator iter = tokens.iterator(); iter.hasNext(); ) {
            Token token = (Token) iter.next();
            if (token instanceof UsernameToken) {
                return true;
            }
        }

        return false;
    }

    private boolean isRefIdPresent(ArrayList refList, String id) {

        if (id != null && id.charAt(0) == '#') {
            id = id.substring(1);
        }

        for (int i = 0; i < refList.size(); i++) {
            WSDataRef dataRef = (WSDataRef) refList.get(i);

            // ArrayList can contain null elements
            if (dataRef == null) {
                continue;
            }
            // Try to get the wsuId of the decrypted element
            String dataRefUri = dataRef.getWsuId();
            // If not found, try the reference Id of encrypted element ( we set the same Id when we
            // decrypted element in WSS4J)
            if (dataRefUri == null) {
                dataRefUri = dataRef.getDataref();
            }
            if (dataRefUri != null && dataRefUri.equals(id)) {
                return true;
            }
        }

        return false;

    }

    public static WSSecurityEngineResult[] fetchActionResults(Vector wsResultVector, int action) {
        List wsResult = new ArrayList();

        // Find the part of the security result that matches the given action
        for (int i = 0; i < wsResultVector.size(); i++) {
            // Check the result of every action whether it matches the given action
            WSSecurityEngineResult result = (WSSecurityEngineResult) wsResultVector.get(i);
            int resultAction = ((java.lang.Integer) result.get(WSSecurityEngineResult.TAG_ACTION))
                    .intValue();
            if (resultAction == action) {
                wsResult.add((WSSecurityEngineResult) wsResultVector.get(i));
            }
        }

        return (WSSecurityEngineResult[]) wsResult.toArray(new WSSecurityEngineResult[wsResult
                .size()]);
    }

    private boolean isRefIdPresent(ArrayList refList, QName qname) {

        for (int i = 0; i < refList.size(); i++) {
            WSDataRef dataRef = (WSDataRef) refList.get(i);

            // ArrayList can contain null elements
            if (dataRef == null) {
                continue;
            }
            // QName of the decrypted element
            QName dataRefQName = dataRef.getName();

            if (dataRefQName != null && dataRefQName.equals(qname)) {
                return true;
            }

        }

        return false;

    }

    /*
    * Verify timestamp of the SAML Token.
    */
    protected boolean verifySAMLTokenTimestamp(Timestamp timestamp, RampartMessageData rmd)
            throws RampartException {

        long now = Calendar.getInstance().getTimeInMillis();
        long maxSkew = RampartUtil.getTimestampMaxSkew(rmd);

        Calendar cre = timestamp.getCreated();
        if (cre != null) {
            // adjust 'now' with allowed timeskew

            long upperLimit = now;
            if (maxSkew > 0) {
                upperLimit += (maxSkew * 1000);
            }

            // fail if ts->Created is after 'now'
            if (cre.getTimeInMillis() > upperLimit) {
                return false;
            }
        }

        // fail if ts->expires has passed by
        Calendar exp = timestamp.getExpires();
        if (exp != null) {
            if (maxSkew > 0) {
                now -= (maxSkew * 1000);
            }
            if (exp.getTimeInMillis() < now) {
                return false;
            }
        }

        return true;
    }

}
