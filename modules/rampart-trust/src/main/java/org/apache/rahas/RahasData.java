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
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.impl.dom.factory.OMDOMFactory;
import org.apache.axiom.om.util.Base64;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.axis2.context.MessageContext;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.KerberosTokenPrincipal;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.opensaml.saml.saml2.core.Assertion;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Vector;
import java.util.Iterator;

/**
 * Common data items on WS-Trust request messages
 */
public class RahasData {

    private MessageContext inMessageContext;

    private OMElement rstElement;

    private int version = -1;

    private String wstNs;

    private String requestType;

    private String tokenType;
    
    private String tokenId;

    private int keysize = -1;

    private String computedKeyAlgo;

    private String keyType;

    private String appliesToAddress;
    
    private OMElement appliesToEpr;

    private Principal principal;

    private X509Certificate clientCert;

    private byte[] ephmeralKey;

    private byte[] requestEntropy;

    private byte[] responseEntropy;

    private String addressingNs;

    private String soapNs;
    
    private OMElement claimElem;
    
    private String  claimDialect;
    
//    private SAMLAssertion assertion;
    
    private Assertion saml2Assertion;

    private String actAs;
    
    private String overridenSubjectValue;

    /**
     * Create a new RahasData instance and populate it with the information from
     * the request.
     *
     * @throws TrustException <code>RequestSecurityToken</code> element is invalid.
     */
    public RahasData(MessageContext inMessageContext) throws TrustException {

        this.inMessageContext = inMessageContext;

        //Check for an authenticated Principal
        this.processWSS4JSecurityResults();

        // Find out the incoming addressing version
        this.addressingNs = (String) this.inMessageContext
                .getProperty(AddressingConstants.WS_ADDRESSING_VERSION);
        
        if ((this.rstElement = (OMElement) inMessageContext
                .getProperty(RahasConstants.PASSIVE_STS_RST)) == null) {
            this.rstElement = this.inMessageContext.getEnvelope().getBody().getFirstElement();
        }

        this.soapNs = this.inMessageContext.getEnvelope().getNamespace()
                .getNamespaceURI();

        this.wstNs = this.rstElement.getNamespace().getNamespaceURI();

        int ver = TrustUtil.getWSTVersion(this.wstNs);

        if (ver == -1) {
            throw new TrustException(TrustException.INVALID_REQUEST);
        } else {
            this.version = ver;
        }

        this.processRequestType();

        this.processTokenType();

        this.processKeyType();

        this.processKeySize();

        this.processAppliesTo();

        this.processEntropy();
        
        this.processClaims();
        
        this.processValidateTarget();
        
        this.processRenewTarget();

        this.processActAs();

    }

    /**
     * Processes the authenticated user information from the WSS4J security
     * results.
     *
     * @throws TrustException
     */
    private void processWSS4JSecurityResults() throws TrustException {

        /*
         * User can be identifier using a UsernameToken or a certificate - If a
         * certificate is found then we use that to - identify the user and -
         * encrypt the response (if required) - If a UsernameToken is found then
         * we will not be encrypting the response
         */

        Vector results;
        if ((results = (Vector) this.inMessageContext
                .getProperty(WSHandlerConstants.RECV_RESULTS)) == null) {
            throw new TrustException(TrustException.REQUEST_FAILED);
        } else {

            for (int i = 0; i < results.size(); i++) {
                WSHandlerResult rResult = (WSHandlerResult) results.get(i);
                Vector wsSecEngineResults = rResult.getResults();

                for (int j = 0; j < wsSecEngineResults.size(); j++) {
                    WSSecurityEngineResult wser = (WSSecurityEngineResult) wsSecEngineResults
                            .get(j);
                    Object principalObject = wser.get(WSSecurityEngineResult.TAG_PRINCIPAL);
                    int act = ((Integer)wser.get(WSSecurityEngineResult.TAG_ACTION)).
                            intValue();
                    if (act == WSConstants.SIGN && principalObject != null) {
                        this.clientCert = (X509Certificate) wser
                                .get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                        this.principal = (Principal)principalObject;
                    } else if (act == WSConstants.UT && principalObject != null) {
                        this.principal = (Principal)principalObject;
                    } else if (act == WSConstants.BST) {
                        final X509Certificate[] certificates = 
                            (X509Certificate[]) wser
                                .get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
						if (certificates != null && certificates.length > 0) {
							this.clientCert = certificates[0];
							this.principal = this.clientCert.getSubjectDN();
						}
					} else if (act == WSConstants.ST_UNSIGNED) {
						String samlVersion = (String) wser.get("samlVersion");
						if ("urn:oasis:names:tc:SAML:2.0:assertion".equals(samlVersion)) {
							this.saml2Assertion = (Assertion) wser
									.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
						} else {
                            throw new TrustException("SAML 1.x is not supported");
						}
					} else if (act == WSConstants.KERBEROS || act == WSConstants.KERBEROS_SIGN) {
						this.principal = (KerberosTokenPrincipal) principalObject;

					}

                }
            }
			// If the principal or a SAML assertion is missing
			if (this.principal == null && (saml2Assertion == null)) {
				throw new TrustException(TrustException.REQUEST_FAILED);
			}
        }
    }

    private void processAppliesTo() throws TrustException {

        OMElement appliesToElem = this.rstElement
                .getFirstChildWithName(new QName(RahasConstants.WSP_NS,
                                                 RahasConstants.IssuanceBindingLocalNames.
                                                         APPLIES_TO));

        if (appliesToElem != null) {
            OMElement eprElem = appliesToElem.getFirstElement();
            this.appliesToEpr = eprElem;
            
            // If there were no addressing headers
            // The find the addressing version using the EPR element
            if (this.addressingNs == null) {
                this.addressingNs = eprElem.getNamespace()
                        .getNamespaceURI();
            }

            if (eprElem != null) {
                
                //Of the epr is a web service then try to get the addr
                
                OMElement addrElem = eprElem
                        .getFirstChildWithName(new QName(
                                this.addressingNs,
                                AddressingConstants.EPR_ADDRESS));
                if (addrElem != null && addrElem.getText() != null
                    && !"".equals(addrElem.getText().trim())) {
                    this.appliesToAddress = addrElem.getText().trim();
                } 
            } else {
                throw new TrustException("invalidAppliesToElem");
            }
        }
    }

    private void processRequestType() throws TrustException {
        OMElement reqTypeElem = this.rstElement
                .getFirstChildWithName(new QName(this.wstNs,
                                                 RahasConstants.LocalNames.REQUEST_TYPE));

        if (reqTypeElem == null ||
            reqTypeElem.getText() == null ||
            reqTypeElem.getText().trim().length() == 0) {
            throw new TrustException(TrustException.INVALID_REQUEST);
        } else {
            this.requestType = reqTypeElem.getText().trim();
        }
    }

    private void processTokenType() {
        OMElement tokTypeElem = this.rstElement
                .getFirstChildWithName(new QName(this.wstNs,
                                                 RahasConstants.LocalNames.TOKEN_TYPE));

        if (tokTypeElem != null && tokTypeElem.getText() != null
            && !"".equals(tokTypeElem.getText().trim())) {
            this.tokenType = tokTypeElem.getText().trim();
        }
    }

    /**
     * Find the value of the KeyType element of the RST
     */
    private void processKeyType() {
        OMElement keyTypeElem = this.rstElement
                .getFirstChildWithName(new QName(this.wstNs,
                                                 RahasConstants.IssuanceBindingLocalNames.KEY_TYPE));
        if (keyTypeElem != null) {
            String text = keyTypeElem.getText();
            if (text != null && !"".equals(text.trim())) {
                this.keyType = text.trim();
            }
        }
    }

    /**
     * Finds the KeySize and creates an empty ephmeral key.
     *
     * @throws TrustException
     */
    private void processKeySize() throws TrustException {
        OMElement keySizeElem =
                this.rstElement
                        .getFirstChildWithName(new QName(this.wstNs,
                                                         RahasConstants.IssuanceBindingLocalNames.
                                                                 KEY_SIZE));
        if (keySizeElem != null) {
            String text = keySizeElem.getText();
            if (text != null && !"".equals(text.trim())) {
                try {
                    //Set key size
                    this.keysize = Integer.parseInt(text.trim());

                    //Create an empty array to hold the key
                    this.ephmeralKey = new byte[this.keysize/8];
                } catch (NumberFormatException e) {
                    throw new TrustException(TrustException.INVALID_REQUEST,
                                             new String[]{"invalid wst:Keysize value"}, e);
                }
            }
        }
        this.keysize = -1;
    }
    
    /**
     * Processes a claims.
     *
     */
    private void processClaims() throws TrustException{
        	claimElem = this.rstElement
        			.getFirstChildWithName(new QName(this.wstNs,
        					RahasConstants.IssuanceBindingLocalNames.CLAIMS));
        	
        	if(claimElem != null){
        		claimDialect = claimElem.getAttributeValue(new QName(this.wstNs,
        					RahasConstants.ATTR_CLAIMS_DIALECT));
        	}
    	
    }
    
    private void processValidateTarget()throws TrustException{
        
        OMElement validateTargetElem  = this.rstElement
                                .getFirstChildWithName(new QName(this.wstNs,
                                               RahasConstants.LocalNames.VALIDATE_TARGET));
        
        if (validateTargetElem != null) {
        
            OMElement strElem = validateTargetElem.getFirstChildWithName(new QName(WSConstants.WSSE_NS,
                                                   "SecurityTokenReference"));
            
            Element elem = (Element)(new StAXOMBuilder(new OMDOMFactory(), 
                    strElem.getXMLStreamReader()).getDocumentElement());
            
            try {
                SecurityTokenReference str = new SecurityTokenReference((Element)elem);
                if (str.containsReference()) {
                    tokenId = str.getReference().getURI();
                } else if(str.containsKeyIdentifier()){
                	tokenId = str.getKeyIdentifierValue();
                }
            } catch (WSSecurityException e) {
                throw new TrustException("errorExtractingTokenId",e);
            } 
        }
    }
    
    private void processRenewTarget()throws TrustException{
        
        OMElement renewTargetElem  = this.rstElement
                                .getFirstChildWithName(new QName(this.wstNs,
                                               RahasConstants.LocalNames.RENEW_TARGET));
        if (renewTargetElem != null) {
        
            OMElement strElem = renewTargetElem.getFirstChildWithName(new QName(WSConstants.WSSE_NS,
                                                   "SecurityTokenReference"));
            
            Element elem = (Element)(new StAXOMBuilder(new OMDOMFactory(), 
                    strElem.getXMLStreamReader()).getDocumentElement());
            
            try {
                SecurityTokenReference str = new SecurityTokenReference((Element)elem);
                if (str.containsReference()) {
                    tokenId = str.getReference().getURI();
                } else if(str.containsKeyIdentifier()){
                	tokenId = str.getKeyIdentifierValue();
                }
                if(tokenId == null){
                    if(str.containsKeyIdentifier()){
                        tokenId = str.getKeyIdentifierValue();
                    }
                }
            } catch (WSSecurityException e) {
                throw new TrustException("errorExtractingTokenId",e);
            }      
        }
    }

    /**
     * Process wst:Entropy element in the request.
     */
    private void processEntropy() throws TrustException {
        OMElement entropyElem = this.rstElement
                .getFirstChildWithName(new QName(this.wstNs,
                                                 RahasConstants.IssuanceBindingLocalNames.ENTROPY));

        if (entropyElem != null) {
            OMElement binSecElem = entropyElem.getFirstElement();
            if (binSecElem != null && binSecElem.getText() != null
                && !"".equals(binSecElem.getText())) {
                this.requestEntropy = Base64.decode(binSecElem.getText());
            } else {
                throw new TrustException("malformedEntropyElement",
                                         new String[]{entropyElem.toString()});
            }

        }
    }



    /**
     * This method is used to process the "ActAs" element, if present in the RST. This method is introduced in
     * WS-Trust 1.4  
     * @throws TrustException
     */
    private void processActAs() throws TrustException {
        // ActAs element is only supported since Ws-Trust 1.4, so return if a prior version
        if (this.version < 3) {
            return;
        }
        OMElement actAsElem = this.rstElement.getFirstChildWithName(new QName(this.wstNs,
                RahasConstants.LocalNames.ACTAS, RahasConstants.WST_PREFIX));
        String subject = null;

        // If there is no identity delegation
        if (actAsElem == null) {
            return;
        }

        //If there is an identity delegation
        else {
            OMElement samlAssertion = actAsElem.getFirstElement();
            String samlNamespace = samlAssertion.getNamespace().getNamespaceURI();

            //In case of a SAML assertion
            if (samlNamespace.equals(RahasConstants.NS_SAML_10)) {
                // In SAML1.1 each stmt has a subject, giving priority to AuthenticationStatement
                OMElement stmtElem = samlAssertion.getFirstChildWithName(new QName(RahasConstants.NS_SAML_10,
                        RahasConstants.LocalNames.SAML1_AUTH_STMT));

                //If there is no AuthenticationStatement, look for an AttributeStatement
                if(stmtElem == null){
                    stmtElem = samlAssertion.getFirstChildWithName(new QName(RahasConstants.NS_SAML_10,
                            RahasConstants.LocalNames.ATTR_STMT));
                }

                OMElement subjectElem = null;
                 //Get the subject
                if (stmtElem != null) {
                    subjectElem = stmtElem.getFirstChildWithName(new QName(RahasConstants.NS_SAML_10,
                            RahasConstants.LocalNames.SUBJECT));
                }

                OMElement nameIDElem = null;

                //Get the NameIdentifier elem
                if(subjectElem != null){
                    nameIDElem = subjectElem.getFirstChildWithName(new QName(RahasConstants.NS_SAML_10,
                            RahasConstants.LocalNames.SAML1_NAMEID));
                }

                if (nameIDElem != null) {
                    subject = nameIDElem.getText();
                }
                 // Get the name of the subject from the Attribute Statement
                else {
                    OMElement attrStmt = samlAssertion.getFirstChildWithName(new QName(RahasConstants.NS_SAML_10,
                            RahasConstants.LocalNames.ATTR_STMT));
                    if (attrStmt != null) {
                        Iterator attrItr = attrStmt.getChildrenWithName(new QName(RahasConstants.NS_SAML_10,
                                RahasConstants.LocalNames.ATTR));

                        // Go through each attribute until a name attribute is found.
                        while (attrItr.hasNext()) {
                            OMElement attrElem = (OMElement) attrItr.next();
                            if (attrElem.getAttribute(new QName("Name")) != null && attrElem.
                                    getAttribute(new QName("Name")).getAttributeValue().toUpperCase().equals("NAME")) {
                                OMElement attrValElem = attrElem.getFirstChildWithName(new QName(RahasConstants.
                                        LocalNames.ATTR_VALUE));
                                if (attrValElem != null) {
                                    subject = attrValElem.getText();
                                } else {
                                    throw new TrustException("Empty AttributeValue element in the SAML Assertion");
                                }
                            }
                        }
                    } else {
                        throw new TrustException("To process an ActAs element, either the NameID of the SAML subject or " +
                                "an attribute with the Name should be present.");
                    }
                }
            }

            // In case of a SAML2.0 Assertion
            else if (samlNamespace.equals(RahasConstants.NS_SAML_20)) {

                OMElement subjectElem = samlAssertion.getFirstChildWithName(new QName(RahasConstants.NS_SAML_20,
                        RahasConstants.LocalNames.SUBJECT, RahasConstants.SAML_PREFIX));

                OMElement nameIDElem = null;

                if (subjectElem != null) {
                    // First try to get the subject from the NameID element, if fails try an attribute stmt.
                    nameIDElem = subjectElem.getFirstChildWithName(new QName(RahasConstants.NS_SAML_20,
                            RahasConstants.LocalNames.SAML2_NAMEID, RahasConstants.SAML_PREFIX));
                }


                if (nameIDElem != null) {
                    subject = nameIDElem.getText();
                }

                // Get the name of the subject from the Attribute Statement
                else {
                    OMElement attrStmt = samlAssertion.getFirstChildWithName(new QName(RahasConstants.NS_SAML_20,
                            RahasConstants.LocalNames.ATTR_STMT, RahasConstants.SAML_PREFIX));
                    if (attrStmt != null) {
                        Iterator attrItr = attrStmt.getChildElements();

                        // Go through each attribute until a name attribute is found.
                        while (attrItr.hasNext()) {
                            OMElement attrElem = (OMElement) attrItr.next();
                            if (attrElem.getAttribute(new QName("Name")) != null && attrElem.
                                    getAttribute(new QName("Name")).getAttributeValue().toUpperCase().equals("NAME")) {
                                OMElement attrValElem = attrElem.getFirstChildWithName(new QName(RahasConstants.NS_SAML_20,
                                        RahasConstants.LocalNames.ATTR_VALUE, RahasConstants.SAML_PREFIX));
                                if (attrValElem != null) {
                                    subject = attrValElem.getText();
                                } else {
                                    throw new TrustException("Empty AttributeValue element in the SAML Assertion");
                                }
                            }
                        }
                    } else {
                        throw new TrustException("To process an ActAs element, either the NameID of the SAML subject or " +
                                "an attribute with the Name should be present.");
                    }
                }
            } else {
                throw new TrustException("Unsupported SAML version.");
            }

            if( subject == null ){
                throw new TrustException("To process an ActAs element, either the NameID of the SAML subject or" +
                        "an attribute with the Name should be present.");
            }

            actAs = subject;
        }
    }

    /**
     * @return Returns the appliesToAddress.
     */
    public String getAppliesToAddress() {
        return appliesToAddress;
    }

    /**
     * @return Returns the clientCert.
     */
    public X509Certificate getClientCert() {
        return clientCert;
    }

    /**
     * @return Returns the computedKeyAlgo.
     */
    public String getComputedKeyAlgo() {
        return computedKeyAlgo;
    }

    /**
     * @return Returns the ephmeralKey.
     */
    public byte[] getEphmeralKey() {
        return ephmeralKey;
    }

    /**
     * @return Returns the inMessageContext.
     */
    public MessageContext getInMessageContext() {
        return inMessageContext;
    }

    /**
     * @return Returns the keysize.
     */
    public int getKeysize() {
        return keysize;
    }

    /**
     * @return Returns the keyType.
     */
    public String getKeyType() {
        return keyType;
    }

    /**
     * @return Returns the principal.
     */
    public Principal getPrincipal() {
        return principal;
    }

    /**
     * @return Returns the requestEntropy.
     */
    public byte[] getRequestEntropy() {
        return requestEntropy;
    }

    /**
     * @return Returns the requestType.
     */
    public String getRequestType() {
        return requestType;
    }

    /**
     * @return Returns the responseEntropy.
     */
    public byte[] getResponseEntropy() {
        return responseEntropy;
    }

    /**
     * @return Returns the rstElement.
     */
    public OMElement getRstElement() {
        return rstElement;
    }

    /**
     * @return Returns the tokenType.
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     * @return Returns the version.
     */
    public int getVersion() {
        return version;
    }

    /**
     * @return Returns the addressingNs.
     */
    public String getAddressingNs() {
        return addressingNs;
    }

    /**
     * @return Returns the wstNs.
     */
    public String getWstNs() {
        return wstNs;
    }

    /**
     * @return Returns the soapNs.
     */
    public String getSoapNs() {
        return soapNs;
    }

    /**
     * @return Returns the tokenId.
     */
    public String getTokenId() {
        return tokenId;
    }

    /**
     * @param responseEntropy The responseEntropy to set.
     */
    public void setResponseEntropy(byte[] responseEntropy) {
        this.responseEntropy = responseEntropy;
    }

    /**
     * @param ephmeralKey The ephmeralKey to set.
     */
    public void setEphmeralKey(byte[] ephmeralKey) {
        this.ephmeralKey = ephmeralKey;
    }

	public String getClaimDialect() {
		return claimDialect;
	}

	public OMElement getClaimElem() {
		return claimElem;
	}

    public OMElement getAppliesToEpr() {
        return appliesToEpr;
    }

    /**
     * @return ActAs element
     */
    public String getActAs() {
        return actAs;
    }
    
	public String getOverridenSubjectValue() {
		return overridenSubjectValue;
	}

	public void setOverridenSubjectValue(String overridenSubjectValue) {
		this.overridenSubjectValue = overridenSubjectValue;
	}

}
