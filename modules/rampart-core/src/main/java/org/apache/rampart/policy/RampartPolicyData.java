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

package org.apache.rampart.policy;

import org.apache.axis2.policy.model.MTOMAssertion;
import org.apache.neethi.Policy;
import org.apache.rampart.RampartException;
import org.apache.rampart.policy.model.OptimizePartsConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AlgorithmSuite;
import org.apache.ws.secpolicy.model.SecureConversationToken;
import org.apache.ws.secpolicy.model.SupportingToken;
import org.apache.ws.secpolicy.model.Token;
import org.apache.ws.secpolicy.model.Trust10;
import org.apache.ws.secpolicy.model.Wss10;
import org.apache.ws.secpolicy.model.Wss11;
import org.apache.ws.security.WSEncryptionPart;

import java.util.HashMap;
import java.util.Vector;

public class RampartPolicyData {

    /*
     * Global settings for overall security processing
     */
    private boolean symmetricBinding;
    
    private boolean transportBinding;
    
    private boolean asymmetricBinding;

    private String layout;

    private boolean includeTimestamp;
    
    private boolean includeTimestampOptional;

    private boolean entireHeadersAndBodySignatures;

    private String protectionOrder;

    private boolean signatureProtection;

    private boolean tokenProtection;

    private boolean signatureConfirmation;

    //Policy namespace
    private String webServiceSecurityPolicyNS = null;

    /*
     * Message tokens for symmetrical binding
     */
    private Token encryptionToken;

    private Token signatureToken;
    
    
    /*
     * Message token for transport binding
     */
    private Token transportToken;

    /*
     * Message tokens for asymmetrical binding
     */
    private Token recipientToken; // used to encrypt data to

    // receipient

    private Token initiatorToken; // used to sign data by

    // initiator

    /*
     * Which parts or elements of the message to sign/encrypt with the messagen
     * tokens. Parts or elements to sign/encrypt with supporting tokens are
     * stored together with the tokens (see WSS4JPolicyToken).
     */
    private boolean signBody;

    private boolean encryptBody;
    
    private boolean signAttachments;
    
    private boolean encryptAttachments;
    
    private boolean signBodyOptional;

    private boolean encryptBodyOptional;
    
    private boolean signAttachmentsOptional;
    
    private boolean encryptAttachmentsOptional;

    private boolean signAllHeaders;

    private Vector signedParts = new Vector();

    private Vector signedElements = new Vector();

    private Vector encryptedParts = new Vector();

    private Vector encryptedElements = new Vector();
    
    private Vector requiredElements = new Vector();
    
    private Vector contentEncryptedElements = new Vector();
    
    private HashMap declaredNamespaces = new HashMap();

    /*
     * Holds the supporting tokens elements
     */
    //private SupportingToken supportingTokens;

    private SupportingToken signedSupportingTokens;

    private SupportingToken endorsingSupportingTokens;

    private SupportingToken signedEndorsingSupportingTokens;
    
    private SupportingToken encryptedSupportingTokens;

    private SupportingToken signedEncryptedSupportingTokens;

    private SupportingToken endorsingEncryptedSupportingTokens;

    private SupportingToken signedEndorsingEncryptedSupportingTokens;
    
    private AlgorithmSuite algorithmSuite;
    
    private RampartConfig rampartConfig;
    
    private MTOMAssertion mtomAssertion;
    
    private Trust10 trust10;
    
    private HashMap supportingTokensIdMap;
    private HashMap signedSupportingTokensIdMap;
    private HashMap endorsingSupportingTokensIdMap;
    private HashMap signedEndorsingSupportingTokensIdMap;
    
    private Wss10 wss10;
    private Wss11 wss11;
    
    private Policy issuerPolicy;
    
    private Vector supportingPolicyData = new Vector();
    
    private Vector supportingTokens = new Vector();



    public String getWebServiceSecurityPolicyNS() {
        return webServiceSecurityPolicyNS;
    }

    public void setWebServiceSecurityPolicyNS(String webServiceSecurityPolicyNS) {
        this.webServiceSecurityPolicyNS = webServiceSecurityPolicyNS;
    }

    public Vector getSupportingPolicyData() {
        return supportingPolicyData;
    }

    public void addSupportingPolicyData(SupportingPolicyData supportingPolicyData) {
        this.supportingPolicyData.add(supportingPolicyData);
    }       
    
    public boolean isSignBodyOptional() {
		return signBodyOptional;
	}

	public void setSignBodyOptional(boolean signBodyOptional) {
		this.signBodyOptional = signBodyOptional;
	}

	public boolean isEncryptBodyOptional() {
		return encryptBodyOptional;
	}

	public void setEncryptBodyOptional(boolean encryptBodyOptional) {
		this.encryptBodyOptional = encryptBodyOptional;
	}

	public boolean isSignAttachmentsOptional() {
		return signAttachmentsOptional;
	}

	public void setSignAttachmentsOptional(boolean signAttachmentsOptional) {
		this.signAttachmentsOptional = signAttachmentsOptional;
	}

	public boolean isEncryptAttachmentsOptional() {
		return encryptAttachmentsOptional;
	}

	public void setEncryptAttachmentsOptional(boolean encryptAttachmentsOptional) {
		this.encryptAttachmentsOptional = encryptAttachmentsOptional;
	}

	/**
     * @return Returns the symmetricBinding.
     */
    public boolean isSymmetricBinding() {
        return symmetricBinding;
    }

    /**
     * @param symmetricBinding
     *            The symmetricBinding to set.
     */
    public void setSymmetricBinding(boolean symmetricBinding) {
        this.symmetricBinding = symmetricBinding;
    }
    
    /**
     * @return Returns a boolean value indicating whether a Asymmetric Binding
     */
    public boolean isAsymmetricBinding() {
        return asymmetricBinding;
    }

    /**
     * @param asymmetricBinding
     *            boolean value indicating whether a Asymmetric Binding
     */
    public void setAsymmetricBinding(boolean asymmetricBinding) {
        this.asymmetricBinding = asymmetricBinding;
    }
    /**
     * @return Returns the entireHeaderAndBodySignatures.
     */
    public boolean isEntireHeadersAndBodySignatures() {
        return entireHeadersAndBodySignatures;
    }

    /**
     * @param entireHeaderAndBodySignatures
     *            The entireHeaderAndBodySignatures to set.
     */
    public void setEntireHeadersAndBodySignatures(
            boolean entireHeaderAndBodySignatures) {
        this.entireHeadersAndBodySignatures = entireHeaderAndBodySignatures;
    }

    /**
     * @return Returns the includeTimestamp.
     */
    public boolean isIncludeTimestamp() {
        return includeTimestamp;
    }

    /**
     * @param includeTimestamp
     *            The includeTimestamp to set.
     */
    public void setIncludeTimestamp(boolean includeTimestamp) {
        this.includeTimestamp = includeTimestamp;
    } 
    
    public boolean isIncludeTimestampOptional() {
		return includeTimestampOptional;
	}

	public void setIncludeTimestampOptional(boolean includeTimestampOptional) {
		this.includeTimestampOptional = includeTimestampOptional;
	}

	/**
     * @return Returns the layout.
     */
    public String getLayout() {
        return layout;
    }

    /**
     * @param layout
     *            The layout to set.
     */
    public void setLayout(String layout) {
        this.layout = layout;
    }

    /**
     * @return Returns the protectionOrder.
     */
    public String getProtectionOrder() {
        return protectionOrder;
    }

    /**
     * @param protectionOrder
     *            The protectionOrder to set.
     */
    public void setProtectionOrder(String protectionOrder) {
        this.protectionOrder = protectionOrder;
    }

    /**
     * @return Returns the signatureProtection.
     */
    public boolean isSignatureProtection() {
        return signatureProtection;
    }

    /**
     * @param signatureProtection
     *            The signatureProtection to set.
     */
    public void setSignatureProtection(boolean signatureProtection) {
        this.signatureProtection = signatureProtection;
    }

    /**
     * @return Returns the tokenProtection.
     */
    public boolean isTokenProtection() {
        return tokenProtection;
    }

    /**
     * @param tokenProtection
     *            The tokenProtection to set.
     */
    public void setTokenProtection(boolean tokenProtection) {
        this.tokenProtection = tokenProtection;
    }

    /**
     * @return Returns the signatureConfirmation.
     */
    public boolean isSignatureConfirmation() {
        return signatureConfirmation;
    }

    /**
     * @param signatureConfirmation
     *            The signatureConfirmation to set.
     */
    public void setSignatureConfirmation(boolean signatureConfirmation) {
        this.signatureConfirmation = signatureConfirmation;
    }

    /**
     * @return Returns the encryptedElements.
     */
    public Vector getEncryptedElements() {
        return encryptedElements;
    }

    /**
     * @param encElement
     *            The encrypted Element (XPath) to set.
     */
    public void setEncryptedElements(String encElement) {

        encryptedElements.add(encElement);
    }
    
    /**
     * @return Returns the requiredElements.
     */
    public Vector getRequiredElements() {
        return requiredElements;
    }

    /**
     * @param requiredElements
     *            The Required Element (XPath) to set.
     */
    public void setRequiredElements(String reqElement) {
        requiredElements.add(reqElement);
    }
    
    /**
     * @return Returns the contentEncryptedElements.
     */
    public Vector getContentEncryptedElements() {
        return contentEncryptedElements;
    }

    /**
     * @param encElement
     *            The encrypted Element (XPath) to set.
     */
    public void setContentEncryptedElements(String encElement) {

        contentEncryptedElements.add(encElement);
    }

    /**
     * @return Returns the encryptedParts.
     */
    public Vector getEncryptedParts() {
        return encryptedParts;
    }

    /**
     * @param namespace
     *            The namespace of the part.
     * @param element
     *            The part's element name.
     */
    public void setEncryptedParts(String namespace, String element) {
        WSEncryptionPart wep = new WSEncryptionPart(element, namespace,
                "Element");
        encryptedParts.add(wep);
    }
    
    /**
     * @param namespace
     *            The namespace of the part.
     * @param element
     *            The part's element name.
     * @param modifier 
     *            The type of encryption 
     *            Element,Content,Header
     */
    public void setEncryptedParts(String namespace, String element, 
    		                                       String modifier) {
        WSEncryptionPart wep = new WSEncryptionPart(element, namespace,
                modifier);
        encryptedParts.add(wep);
    }
    

    /**
     * @return Returns the encryptBody.
     */
    public boolean isEncryptBody() {
        return encryptBody;
    }

    /**
     * @param encryptBody
     *            The encryptBody to set.
     */
    public void setEncryptBody(boolean encryptBody) {
        this.encryptBody = encryptBody;
    }

    /**
     * @return Returns the signBody.
     */
    public boolean isSignBody() {
        return signBody;
    }

    /**
     * @param signBody
     *            The signBody to set.
     */
    public void setSignBody(boolean signBody) {
        this.signBody = signBody;
    }
    
    /**
     * @return Returns the signAttachments.
     */
    public boolean isSignAttachments() {
        return signAttachments;
    }

    /**
     * @param signAttachments
     *            The signAttachments to set.
     */
    public void setSignAttachments(boolean signAttachments) {
        this.signAttachments = signAttachments;
    }
    
    /**
     * @return Returns the encryptAttachments.
     */
    public boolean isEncryptAttachments() {
        return encryptAttachments;
    }

    /**
     * @param encryptAttachments
     *            The encryptAttachments to set.
     */
    public void setEncryptAttachments(boolean encryptAttachments) {
        this.encryptAttachments = encryptAttachments;
    }

    /**
     * @return Returns the signedElements.
     */
    public Vector getSignedElements() {
        return signedElements;
    }

    /**
     * @param sigElement
     *            The signed Element (XPath) to set.
     */
    public void setSignedElements(String sigElement) {

        signedElements.add(sigElement);
    }

    /**
     * @return Returns the signedParts.
     */
    public Vector getSignedParts() {
        return signedParts;
    }
    
    public HashMap getDeclaredNamespaces() {
        return declaredNamespaces;
    }
    
    public void addDeclaredNamespaces(HashMap namespaces) {
        declaredNamespaces.putAll(namespaces);
    }

    /**
     * @param namespace
     *            The namespace of the part.
     * @param element
     *            The part's element name.
     */
    public void addSignedPart(String namespace, String element) {

        WSEncryptionPart wep = new WSEncryptionPart(element, namespace,
                "Content");
        signedParts.add(wep);
    }

    public void addSignedPart(WSEncryptionPart part) {
        signedParts.add(part);
    }
    
    public void setSignedParts(Vector signedParts) {
        this.signedParts = signedParts;
    }
    
    public void setSupportingTokens(SupportingToken suppTokens)
            throws WSSPolicyException {

        int tokenType = suppTokens.getTokenType();
        if (tokenType == SPConstants.SUPPORTING_TOKEN_SUPPORTING) {
            supportingTokens.add(suppTokens);
        } else if (tokenType == SPConstants.SUPPORTING_TOKEN_SIGNED) {
            signedSupportingTokens = suppTokens;
        } else if (tokenType == SPConstants.SUPPORTING_TOKEN_ENDORSING) {
            endorsingSupportingTokens = suppTokens;
        } else if (tokenType == SPConstants.SUPPORTING_TOKEN_SIGNED_ENDORSING) {
            signedEndorsingSupportingTokens = suppTokens;
        } else if (tokenType == SPConstants.SUPPORTING_TOKEN_ENCRYPTED) {
            encryptedSupportingTokens = suppTokens;
        } else if (tokenType == SPConstants.SUPPORTING_TOKEN_SIGNED_ENCRYPTED) {
            signedEncryptedSupportingTokens = suppTokens;
        } else if (tokenType == SPConstants.SUPPORTING_TOKEN_ENDORSING_ENCRYPTED) {
            endorsingEncryptedSupportingTokens = suppTokens;
        } else if (tokenType == SPConstants.SUPPORTING_TOKEN_SIGNED_ENDORSING_ENCRYPTED) {
            signedEndorsingEncryptedSupportingTokens = suppTokens;
        }
    }
    
    

    /**
     * @return Returns the rampartConfig.
     */
    public RampartConfig getRampartConfig() {
        return rampartConfig;
    }

    /**
     * @return Returns the encryptionToken.
     */
    public Token getEncryptionToken() {
        return encryptionToken;
    }

    /**
     * @param encryptionToken The encryptionToken to set.
     */
    public void setEncryptionToken(Token encryptionToken) {
        this.encryptionToken = encryptionToken;
        this.extractIssuerPolicy(encryptionToken);
    }

    /**
     * @return Returns the initiatorToken.
     */
    public Token getInitiatorToken() {
        return initiatorToken;
    }

    /**
     * @param initiatorToken The initiatorToken to set.
     */
    public void setInitiatorToken(Token initiatorToken) {
        this.initiatorToken = initiatorToken;
    }
    
    /**
     * @return Returns the TransportToken.
     */
    public Token getTransportToken() {
        return transportToken;
    }

    /**
     * @param transportToken The TransportToken to set.
     */
    public void setTransportToken(Token transportToken) {
        this.transportToken = transportToken;
    }

    /**
     * @return Returns the recipientToken.
     */
    public Token getRecipientToken() {
        return recipientToken;
    }

    /**
     * @param recipientToken The recipientToken to set.
     */
    public void setRecipientToken(Token recipientToken) {
        this.recipientToken = recipientToken;
    }
    
    public void setProtectionToken(Token protectionToken) {
        this.setEncryptionToken(protectionToken);
        this.setSignatureToken(protectionToken);
        this.extractIssuerPolicy(protectionToken);
    }

    /**
     * @return Returns the signatureToken.
     */
    public Token getSignatureToken() {
        return signatureToken;
    }

    /**
     * @param signatureToken The signatureToken to set.
     */
    public void setSignatureToken(Token signatureToken) {
        this.signatureToken = signatureToken;
        this.extractIssuerPolicy(signatureToken);
    }

    /**
     * @return Returns the signedEndorsingSupportingToken.
     */
    public SupportingToken getSignedEndorsingSupportingTokens() {
        return signedEndorsingSupportingTokens;
    }

    /**
     * @param signedEndorsingSupportingTokens The signedEndorsingSupportingToken to set.
     */
    public void setSignedEndorsingSupportingTokens(
            SupportingToken signedEndorsingSupportingTokens) {
        this.signedEndorsingSupportingTokens = signedEndorsingSupportingTokens;
    }
    
    /**
     * @return Returns the signedEndorsingEncryptedSupportingToken.
     */
    public SupportingToken getSignedEndorsingEncryptedSupportingTokens() {
        return signedEndorsingEncryptedSupportingTokens;
    }

    /**
     * @param signedEndorsingEncryptedSupportingTokens The signedEndorsingEncryptedSupportingToken to set.
     */
    public void setSignedEndorsingEncryptedSupportingTokens(
            SupportingToken signedEndorsingEncryptedSupportingTokens) {
        this.signedEndorsingEncryptedSupportingTokens = signedEndorsingEncryptedSupportingTokens;
    }

    /**
     * @return Returns the signedSupportingToken.
     */
    public SupportingToken getSignedSupportingTokens() {
        return signedSupportingTokens;
    }

    /**
     * @param signedSupportingTokens The signedSupportingToken to set.
     */
    public void setSignedSupportingTokens(SupportingToken signedSupportingTokens) {
        this.signedSupportingTokens = signedSupportingTokens;
    }
    
    /**
     * @return Returns the signedEncryptedSupportingToken.
     */
    public SupportingToken getSignedEncryptedSupportingTokens() {
        return signedEncryptedSupportingTokens;
    }

    /**
     * @param signedEncryptedSupportingTokens The signedEncryptedSupportingToken to set.
     */
    public void setSignedEncryptedSupportingTokens(SupportingToken signedEncryptedSupportingTokens) {
        this.signedEncryptedSupportingTokens = signedEncryptedSupportingTokens;
    }

    /**
     * @return Returns the supportingTokenList.
     */
    public Vector getSupportingTokensList() {
        return supportingTokens;
    }
    
    public SupportingToken getSupportingTokens() {
        if (supportingTokens.size() > 0) {
            return (SupportingToken) supportingTokens.get(0);
        } else {
            return null;
        }
    }
    
    /**
     * @param encryptedSupportingTokens The encryptedSupportingToken to set.
     */
    public void setEncryptedSupportingTokens(SupportingToken encryptedSupportingTokens) {
        this.encryptedSupportingTokens = encryptedSupportingTokens;
    }
    
    /**
     * @return Returns the encryptedSupportingToken.
     */
    public SupportingToken getEncryptedSupportingTokens() {
        return encryptedSupportingTokens;
    }

    /**
     * @param endorsingSupportingTokens The endorsingSupportingToken to set.
     */
    public void setEndorsingSupportingTokens(SupportingToken endorsingSupportingTokens) {
        this.endorsingSupportingTokens = endorsingSupportingTokens;
    }

    /**
     * @return Returns the endorsingSupportingToken.
     */
    public SupportingToken getEndorsingSupportingTokens() {
        return endorsingSupportingTokens;
    }
    
    /**
     * @param endorsingEncryptedSupportingTokens The endorsingEncryptedSupportingToken to set.
     */
    public void setEndorsingEncryptedSupportingTokens(SupportingToken endorsingEncryptedSupportingTokens) {
        this.endorsingEncryptedSupportingTokens = endorsingEncryptedSupportingTokens;
    }

    /**
     * @return Returns the endorsingEncryptedSupportingToken.
     */
    public SupportingToken getEndorsingEncryptedSupportingTokens() {
        return endorsingEncryptedSupportingTokens;
    }

    /**
     * @return Returns the algorithmSuite.
     */
    public AlgorithmSuite getAlgorithmSuite() {
        return algorithmSuite;
    }

    /**
     * @param algorithmSuite The algorithmSuite to set.
     */
    public void setAlgorithmSuite(AlgorithmSuite algorithmSuite) {
        this.algorithmSuite = algorithmSuite;
    }

    /**
     * @return Returns the trust10.
     */
    public Trust10 getTrust10() {
        return trust10;
    }

    /**
     * @param trust10 The trust10 to set.
     */
    public void setTrust10(Trust10 trust10) {
        this.trust10 = trust10;
    }

    /**
     * @param rampartConfig The rampartConfig to set.
     */
    public void setRampartConfig(RampartConfig rampartConfig) {
        this.rampartConfig = rampartConfig;
    }

    /**
     * @return Returns the transportBinding.
     */
    public boolean isTransportBinding() {
        return transportBinding;
    }

    /**
     * @param transportBinding The transportBinding to set.
     */
    public void setTransportBinding(boolean transportBinding) {
        this.transportBinding = transportBinding;
    }

    
    /**
     * Add the given token and id to the map. 
     * @param token
     * @param id
     */
    public void setSupporttingtokenId(Token token, String id, int type) throws RampartException {
        
        HashMap tokenMap = null;
        switch (type) {
        case SPConstants.SUPPORTING_TOKEN_SUPPORTING:
            if(this.supportingTokensIdMap == null) {
                this.supportingTokensIdMap = new HashMap();
            }
            tokenMap = this.supportingTokensIdMap;
            break;

        case SPConstants.SUPPORTING_TOKEN_SIGNED:
            if(this.signedSupportingTokensIdMap == null) {
                this.signedSupportingTokensIdMap = new HashMap();
            }
            tokenMap = this.signedSupportingTokensIdMap;
            break;
            
        case SPConstants.SUPPORTING_TOKEN_ENDORSING:
            if(this.endorsingSupportingTokensIdMap == null) {
                this.endorsingSupportingTokensIdMap = new HashMap();
            }
            tokenMap = this.endorsingSupportingTokensIdMap;
            break;
            
        case SPConstants.SUPPORTING_TOKEN_SIGNED_ENDORSING:
            if(this.signedEndorsingSupportingTokensIdMap == null) {
                this.signedEndorsingSupportingTokensIdMap = new HashMap();
            }
            tokenMap = this.signedEndorsingSupportingTokensIdMap;
            break;
            
        default:
            throw new RampartException("invalidSupportingVersionType",
                    new String[] { Integer.toString(type) });
        }
        
        tokenMap.put(token, id);
    }
    
    public String getSupportingTokenID(Token token, int type)
            throws RampartException {
        switch (type) {
        case SPConstants.SUPPORTING_TOKEN_SUPPORTING:
            if(this.supportingTokensIdMap != null) {
                return (String)this.supportingTokensIdMap.get(token);
            }
            return null;

        case SPConstants.SUPPORTING_TOKEN_SIGNED:
            if(this.signedSupportingTokensIdMap != null) {
                return (String)this.signedSupportingTokensIdMap.get(token);
            }
            return null;
            
        case SPConstants.SUPPORTING_TOKEN_ENDORSING:
            if(this.endorsingSupportingTokensIdMap != null) {
                return (String)this.endorsingSupportingTokensIdMap.get(token);
            }
            return null;
            
        case SPConstants.SUPPORTING_TOKEN_SIGNED_ENDORSING:
            if(this.signedEndorsingSupportingTokensIdMap == null) {
                this.signedEndorsingSupportingTokensIdMap = new HashMap();
            }
            return null;

        default:
            throw new RampartException("invalidSupportingVersionType",
                    new String[] { Integer.toString(type) });
        }
    }

    public Wss10 getWss10() {
        return wss10;
    }

    public void setWss10(Wss10 wss10) {
        this.wss10 = wss10;
    }

    public Wss11 getWss11() {
        return wss11;
    }

    public void setWss11(Wss11 wss11) {
        this.wss11 = wss11;
    }
    
    private void extractIssuerPolicy(Token token) {
        if(token instanceof SecureConversationToken && this.issuerPolicy == null) {
            this.issuerPolicy = ((SecureConversationToken)token).getBootstrapPolicy();
        }
    }

    public Policy getIssuerPolicy() {
        return issuerPolicy;
    }
    
    public void setMTOMAssertion(MTOMAssertion mtomAssertion){
    	this.mtomAssertion =  mtomAssertion;   	
    }
    
    public MTOMAssertion getMTOMAssertion(){
    	return mtomAssertion;
    }

    public boolean isSignAllHeaders() {
        return signAllHeaders;
    }

    public void setSignAllHeaders(boolean signAllHeaders) {
        this.signAllHeaders = signAllHeaders;
    }
    
    public boolean isMTOMSerialize(){
    	if(mtomAssertion == null){
    		return false;
    	}
    	else if(mtomAssertion.isOptional()==false){
    		return true;
    	}
    	else
    		return false;
    }
    
    public OptimizePartsConfig getOptimizePartsConfig(){
    	return rampartConfig.getOptimizeParts();
    }
   
     
}
