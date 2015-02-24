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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.TrustException;
import org.apache.rampart.RampartConstants;
import org.apache.rampart.RampartException;
import org.apache.rampart.RampartMessageData;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.SupportingPolicyData;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.AlgorithmSuite;
import org.apache.ws.secpolicy.model.IssuedToken;
import org.apache.ws.secpolicy.model.KerberosToken;
import org.apache.ws.secpolicy.model.SecureConversationToken;
import org.apache.ws.secpolicy.model.SupportingToken;
import org.apache.ws.secpolicy.model.Token;
import org.apache.ws.secpolicy.model.X509Token;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSecDKEncrypt;
import org.apache.ws.security.message.WSSecDKSign;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.message.WSSecSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

public class AsymmetricBindingBuilder extends BindingBuilder {

    private static Log log = LogFactory.getLog(AsymmetricBindingBuilder.class);
    private static Log tlog = LogFactory.getLog(RampartConstants.TIME_LOG);	

    private Token sigToken;

    private WSSecSignature sig;

    private WSSecEncryptedKey encrKey;
    
    private String encryptedKeyId;
    
    private byte[] encryptedKeyValue;

    private Vector signatureValues = new Vector();

    private Element encrTokenElement;
    
    private Element sigDKTElement;
    
    private Element encrDKTElement;

    private Vector sigParts = new Vector();
    
    private Element signatureElement; 
    
    public void build(RampartMessageData rmd) throws RampartException {
        log.debug("AsymmetricBindingBuilder build invoked");

        RampartPolicyData rpd = rmd.getPolicyData();
        if (rpd.isIncludeTimestamp()) {
            this.addTimestamp(rmd);
        }
        
		if (rmd.isInitiator()) {
			initializeTokens(rmd);
		}

        if (SPConstants.ENCRYPT_BEFORE_SIGNING.equals(rpd.getProtectionOrder())) {
            this.doEncryptBeforeSig(rmd);
        } else {
            this.doSignBeforeEncrypt(rmd);
        }

        log.debug("AsymmetricBindingBuilder build invoked : DONE");
    }

    private void doEncryptBeforeSig(RampartMessageData rmd)
            throws RampartException {
    	
    	long t0 = 0, t1 = 0, t2 = 0;
    	if(tlog.isDebugEnabled()){
    		t0 = System.currentTimeMillis();
    	}
        RampartPolicyData rpd = rmd.getPolicyData();
        Document doc = rmd.getDocument();
        RampartConfig config = rpd.getRampartConfig();

        /*
         * We need to hold on to these two element to use them as refence in the
         * case of encypting the signature
         */
        Element encrDKTokenElem = null;
        WSSecEncrypt encr = null;
        Element refList = null;
        WSSecDKEncrypt dkEncr = null;

        /*
         * We MUST use keys derived from the same token
         */
        Token encryptionToken = null;
        if(rmd.isInitiator()) {
            encryptionToken = rpd.getRecipientToken();
        } else {
            encryptionToken = rpd.getInitiatorToken();
        }
        Vector encrParts = RampartUtil.getEncryptedParts(rmd);
        
        //Signed parts are determined before encryption because encrypted signed  headers
        //will not be included otherwise
        this.sigParts = RampartUtil.getSignedParts(rmd);
        
        if(encryptionToken == null && encrParts.size() > 0) {
            throw new RampartException("encryptionTokenMissing");
        }
        
        if (encryptionToken != null && encrParts.size() > 0) {
            
            //Check for RampartConfig assertion
            if(rpd.getRampartConfig() == null) {
                //We'er missing the extra info rampart needs
                throw new RampartException("rampartConigMissing");
            }
            
            if (encryptionToken.isDerivedKeys()) {
                try {
                    this.setupEncryptedKey(rmd, encryptionToken);
                    // Create the DK encryption builder
                    dkEncr = new WSSecDKEncrypt();
                    dkEncr.setParts(encrParts);
                    dkEncr.setExternalKey(this.encryptedKeyValue, 
                            this.encryptedKeyId);
                    dkEncr.setDerivedKeyLength(rpd.getAlgorithmSuite().getEncryptionDerivedKeyLength()/8);
                    dkEncr.prepare(doc);

                    // Get and add the DKT element
                    this.encrDKTElement = dkEncr.getdktElement();
                    encrDKTokenElem = RampartUtil.appendChildToSecHeader(rmd, this.encrDKTElement);

                    refList = dkEncr.encryptForExternalRef(null, encrParts);

                } catch (WSSecurityException e) {
                    throw new RampartException("errorCreatingEncryptedKey", e);
                } catch (ConversationException e) {
                    throw new RampartException("errorInDKEncr", e);
                }
            } else {
                try {
                    encr = new WSSecEncrypt();
                    encr.setParts(encrParts);
                    encr.setWsConfig(rmd.getConfig());
                    encr.setDocument(doc);
                    RampartUtil.setEncryptionUser(rmd, encr);
                    encr.setSymmetricEncAlgorithm(rpd.getAlgorithmSuite().getEncryption());
                    RampartUtil.setKeyIdentifierType(rmd, encr, encryptionToken);
                    encr.setKeyEncAlgo(rpd.getAlgorithmSuite().getAsymmetricKeyWrap());
                    encr.prepare(doc, RampartUtil.getEncryptionCrypto(config, rmd.getCustomClassLoader()));

                    Element bstElem = encr.getBinarySecurityTokenElement();
                    if (bstElem != null) {
                        RampartUtil.appendChildToSecHeader(rmd, bstElem);
                    }

                    this.encrTokenElement = encr.getEncryptedKeyElement();
                    this.encrTokenElement = RampartUtil.appendChildToSecHeader(rmd,
                            encrTokenElement);

                    refList = encr.encryptForExternalRef(null, encrParts);

                } catch (WSSecurityException e) {
                    throw new RampartException("errorInEncryption", e);
                }
            }

            RampartUtil.appendChildToSecHeader(rmd, refList);
            
            if(tlog.isDebugEnabled()){
            	t1 = System.currentTimeMillis();
            }
            
            this.setInsertionLocation(encrTokenElement);

            RampartUtil.handleEncryptedSignedHeaders(encrParts, this.sigParts, doc);
            
            HashMap sigSuppTokMap = null;
            HashMap endSuppTokMap = null;
            HashMap sgndEndSuppTokMap = null;
            HashMap sgndEncSuppTokMap = null;
            HashMap endEncSuppTokMap = null;
            HashMap sgndEndEncSuppTokMap = null;
            
            if(this.timestampElement != null){
            	sigParts.add(new WSEncryptionPart(RampartUtil
                    .addWsuIdToElement((OMElement) this.timestampElement)));
            }
            
            if (rmd.isInitiator()) {

                // Now add the supporting tokens
                SupportingToken sgndSuppTokens = rpd.getSignedSupportingTokens();
                sigSuppTokMap = this.handleSupportingTokens(rmd, sgndSuppTokens);           
                
                SupportingToken endSuppTokens = rpd.getEndorsingSupportingTokens();
                endSuppTokMap = this.handleSupportingTokens(rmd, endSuppTokens);
                
                SupportingToken sgndEndSuppTokens = rpd.getSignedEndorsingSupportingTokens();           
                sgndEndSuppTokMap = this.handleSupportingTokens(rmd, sgndEndSuppTokens);
                
                SupportingToken sgndEncryptedSuppTokens = rpd.getSignedEncryptedSupportingTokens();
                sgndEncSuppTokMap = this.handleSupportingTokens(rmd, sgndEncryptedSuppTokens);
                
                SupportingToken endorsingEncryptedSuppTokens = rpd.getEndorsingEncryptedSupportingTokens();
                endEncSuppTokMap = this.handleSupportingTokens(rmd, endorsingEncryptedSuppTokens);
                
                SupportingToken sgndEndEncSuppTokens = rpd.getSignedEndorsingEncryptedSupportingTokens();           
                sgndEndEncSuppTokMap = this.handleSupportingTokens(rmd, sgndEndEncSuppTokens);
                
                Vector supportingToks = rpd.getSupportingTokensList();
                for (int i = 0; i < supportingToks.size(); i++) {
                    this.handleSupportingTokens(rmd, (SupportingToken)supportingToks.get(i));
                } 
                
                SupportingToken encryptedSupportingToks = rpd.getEncryptedSupportingTokens();
                this.handleSupportingTokens(rmd, encryptedSupportingToks);
        
                //Setup signature parts
                sigParts = addSignatureParts(sigSuppTokMap, sigParts);
                sigParts = addSignatureParts(sgndEncSuppTokMap, sigParts);
                sigParts = addSignatureParts(sgndEndSuppTokMap, sigParts);
                sigParts = addSignatureParts(sgndEndEncSuppTokMap, sigParts);
                
            } else {
                addSignatureConfirmation(rmd, sigParts);
            }
            
			if ((sigParts.size() > 0 && rmd.isInitiator() && rpd.getInitiatorToken() != null)
					|| (!rmd.isInitiator() && rpd.getRecipientToken() != null)) {
				if (rpd.getInitiatorToken() instanceof IssuedToken) {
					String sigTokId = rmd.getIssuedSignatureTokenId();
					org.apache.rahas.Token sigTok = null;
					Element sigTokElem = null;
					sigToken = rpd.getInitiatorToken();
					if (!(sigToken instanceof KerberosToken)) {
						sigTok = getToken(rmd, sigTokId);
						if (5 == sigToken.getInclusion() || 2 == sigToken.getInclusion()
								|| rmd.isInitiator() && 3 == sigToken.getInclusion())
							sigTokElem = RampartUtil.appendChildToSecHeader(rmd, sigTok.getToken());
						else if (rmd.isInitiator() && (sigToken instanceof X509Token)
								|| (sigToken instanceof SecureConversationToken))
							sigTokElem = RampartUtil.appendChildToSecHeader(rmd, sigTok.getToken());
					}
					if (sigTokElem != null)
						setInsertionLocation(sigTokElem);
					doSymmSignature(rmd, rpd.getInitiatorToken(), sigTok, sigParts);
				} else {
					doSignature(rmd);
				}

			}

            if (rmd.isInitiator()) {
                
                endSuppTokMap.putAll(endEncSuppTokMap);
                // Do endorsed signatures
                Vector endSigVals = this.doEndorsedSignatures(rmd,
                        endSuppTokMap);
                for (Iterator iter = endSigVals.iterator(); iter.hasNext();) {
                    signatureValues.add(iter.next());
                }

                sgndEndSuppTokMap.putAll(sgndEndEncSuppTokMap);
                // Do signed endorsing signatures
                Vector sigEndSigVals = this.doEndorsedSignatures(rmd,
                        sgndEndSuppTokMap);
                for (Iterator iter = sigEndSigVals.iterator(); iter.hasNext();) {
                    signatureValues.add(iter.next());
                }
            }
            
            if(tlog.isDebugEnabled()){
            	t2 = System.currentTimeMillis();
            	tlog.debug("Encryption took :" + (t1 - t0)
            				+", Signature tool :" + (t2 - t1) );
            }

            // Check for signature protection
            if (rpd.isSignatureProtection() && this.mainSigId != null) {
            	long t3 = 0, t4 = 0;
            	if(tlog.isDebugEnabled()){
            		t3 = System.currentTimeMillis();
            	}
                Vector secondEncrParts = new Vector();

                // Now encrypt the signature using the above token
                secondEncrParts.add(new WSEncryptionPart(this.mainSigId,
                        "Element"));
                
                if(rmd.isInitiator()) {
                    for (int i = 0 ; i < encryptedTokensIdList.size(); i++) {
                        secondEncrParts.add(new WSEncryptionPart((String)encryptedTokensIdList.get(i),"Element"));
                    }
                }

                Element secondRefList = null;

                if (encryptionToken.isDerivedKeys()) {
                    try {

                        secondRefList = dkEncr.encryptForExternalRef(null,
                                secondEncrParts);
                        RampartUtil.insertSiblingAfter(rmd, encrDKTokenElem,
                                secondRefList);

                    } catch (WSSecurityException e) {
                        throw new RampartException("errorCreatingEncryptedKey",
                                e);
                    }
                } else {
                    try {
                        // Encrypt, get hold of the ref list and add it
                        secondRefList = encr.encryptForExternalRef(null,
                                secondEncrParts);

                        // Insert the ref list after the encrypted key elem
                        this.setInsertionLocation(RampartUtil
                                .insertSiblingAfter(rmd, encrTokenElement,
                                        secondRefList));
                    } catch (WSSecurityException e) {
                        throw new RampartException("errorInEncryption", e);
                    }
                }
                if(tlog.isDebugEnabled()){
            		t4 = System.currentTimeMillis();
            		tlog.debug("Signature protection took :" + (t4 - t3));
            	}
            }
        }
        
        

    }

    private void doSignBeforeEncrypt(RampartMessageData rmd)
            throws RampartException {
    	
    	long t0 = 0, t1 = 0, t2 = 0;
    	        
        RampartPolicyData rpd = rmd.getPolicyData();
        Document doc = rmd.getDocument();

        HashMap sigSuppTokMap = null;
        HashMap endSuppTokMap = null;
        HashMap sgndEndSuppTokMap = null;
        HashMap sgndEncSuppTokMap = null;
        HashMap endEncSuppTokMap = null;
        HashMap sgndEndEncSuppTokMap = null;
        
        sigParts = RampartUtil.getSignedParts(rmd);
        
        //Add timestamp
        if(this.timestampElement != null){
        	sigParts.add(new WSEncryptionPart(RampartUtil
                .addWsuIdToElement((OMElement) this.timestampElement)));
        }else{
        	this.setInsertionLocation(null);
        }
        
        if(tlog.isDebugEnabled()){
    		t0 = System.currentTimeMillis();
    	}
        
        if (rmd.isInitiator()) {
           
            //      Now add the supporting tokens
            SupportingToken sgndSuppTokens = rpd.getSignedSupportingTokens();
            sigSuppTokMap = this.handleSupportingTokens(rmd, sgndSuppTokens);           
            
            SupportingToken endSuppTokens = rpd.getEndorsingSupportingTokens();
            endSuppTokMap = this.handleSupportingTokens(rmd, endSuppTokens);
            
            SupportingToken sgndEndSuppTokens = rpd.getSignedEndorsingSupportingTokens();           
            sgndEndSuppTokMap = this.handleSupportingTokens(rmd, sgndEndSuppTokens);
            
            SupportingToken sgndEncryptedSuppTokens = rpd.getSignedEncryptedSupportingTokens();
            sgndEncSuppTokMap = this.handleSupportingTokens(rmd, sgndEncryptedSuppTokens);
            
            SupportingToken endorsingEncryptedSuppTokens = rpd.getEndorsingEncryptedSupportingTokens();
            endEncSuppTokMap = this.handleSupportingTokens(rmd, endorsingEncryptedSuppTokens);
            
            SupportingToken sgndEndEncSuppTokens = rpd.getSignedEndorsingEncryptedSupportingTokens();           
            sgndEndEncSuppTokMap = this.handleSupportingTokens(rmd, sgndEndEncSuppTokens);
            
            Vector supportingToks = rpd.getSupportingTokensList();
            for (int i = 0; i < supportingToks.size(); i++) {
                this.handleSupportingTokens(rmd, (SupportingToken)supportingToks.get(i));
            } 
            
            SupportingToken encryptedSupportingToks = rpd.getEncryptedSupportingTokens();
            this.handleSupportingTokens(rmd, encryptedSupportingToks);
    
            //Setup signature parts
            sigParts = addSignatureParts(sigSuppTokMap, sigParts);
            sigParts = addSignatureParts(sgndEncSuppTokMap, sigParts);
            sigParts = addSignatureParts(sgndEndSuppTokMap, sigParts);
            sigParts = addSignatureParts(sgndEndEncSuppTokMap, sigParts);
            
        } else {
            addSignatureConfirmation(rmd, sigParts);
        }

        if( sigParts.size() > 0 && 
                ((rmd.isInitiator() && rpd.getInitiatorToken() != null) || 
                (!rmd.isInitiator() && rpd.getRecipientToken() != null))) {
        	if (rpd.getInitiatorToken() instanceof IssuedToken && rmd.isInitiator()) {
				String sigTokId = rmd.getIssuedSignatureTokenId();
				org.apache.rahas.Token sigTok = null;
				Element sigTokElem = null;
				sigToken = rpd.getInitiatorToken();
				if (!(sigToken instanceof KerberosToken)) {
					sigTok = getToken(rmd, sigTokId);
					if (5 == sigToken.getInclusion() || 2 == sigToken.getInclusion()
							|| rmd.isInitiator() && 3 == sigToken.getInclusion())
						sigTokElem = RampartUtil.appendChildToSecHeader(rmd, sigTok.getToken());
					else if (rmd.isInitiator() && (sigToken instanceof X509Token)
							|| (sigToken instanceof SecureConversationToken))
						sigTokElem = RampartUtil.appendChildToSecHeader(rmd, sigTok.getToken());
				}
				if (sigTokElem != null)
					setInsertionLocation(sigTokElem);
				doSymmSignature(rmd, rpd.getInitiatorToken(), sigTok, sigParts);
			} else {
				doSignature(rmd);
			}
        }
        
        Vector supportingToks = rpd.getSupportingPolicyData();
        for (int i = 0; i < supportingToks.size(); i++) {
            SupportingPolicyData policyData = null;
            if (supportingToks.get(i) != null) {
                policyData = (SupportingPolicyData) supportingToks.get(i);
                Vector supportingSigParts = RampartUtil.getSupportingSignedParts(rmd,
                        policyData);

                if (supportingSigParts.size() > 0
                        && ((rmd.isInitiator() && rpd.getInitiatorToken() != null) || (!rmd
                                .isInitiator() && rpd.getRecipientToken() != null))) {
                    // Do signature for policies defined under SupportingToken.
                    this.doSupportingSignature(rmd, supportingSigParts,policyData);
                }
            }
        }
        
        //Do endorsed signature

        if (rmd.isInitiator()) {
            
            // Adding the endorsing encrypted supporting tokens to endorsing supporting tokens
            endSuppTokMap.putAll(endEncSuppTokMap);
            // Do endorsed signatures
            Vector endSigVals = this.doEndorsedSignatures(rmd,
                    endSuppTokMap);
            for (Iterator iter = endSigVals.iterator(); iter.hasNext();) {
                signatureValues.add(iter.next());
            }

            //Adding the signed endorsed encrypted tokens to signed endorsed supporting tokens
            sgndEndSuppTokMap.putAll(sgndEndEncSuppTokMap);
            // Do signed endorsing signatures
            Vector sigEndSigVals = this.doEndorsedSignatures(rmd,
                    sgndEndSuppTokMap);
            for (Iterator iter = sigEndSigVals.iterator(); iter.hasNext();) {
                signatureValues.add(iter.next());
            }
        }
        
        if(tlog.isDebugEnabled()){
    		t1 = System.currentTimeMillis();
    	}
             
        Vector encrParts = RampartUtil.getEncryptedParts(rmd);
        
        //Check for signature protection
        if(rpd.isSignatureProtection() && this.mainSigId != null) {
            encrParts.add(new WSEncryptionPart(RampartUtil.addWsuIdToElement((OMElement)this.signatureElement), "Element"));
        }
        
        if(rmd.isInitiator()) {
            for (int i = 0 ; i < encryptedTokensIdList.size(); i++) {
                encrParts.add(new WSEncryptionPart((String)encryptedTokensIdList.get(i),"Element"));
            }
        }

        //Do encryption
        Token encrToken;
        if (rmd.isInitiator()) {
            encrToken = rpd.getRecipientToken();
        } else {
            encrToken = rpd.getInitiatorToken();
        }

        if(encrToken != null && encrParts.size() > 0) {
            Element refList = null;
            AlgorithmSuite algorithmSuite = rpd.getAlgorithmSuite();
            if(encrToken.isDerivedKeys()) {
                
                try {
                    WSSecDKEncrypt dkEncr = new WSSecDKEncrypt();
                    
                    if(this.encrKey == null) {
                        this.setupEncryptedKey(rmd, encrToken);
                    }
                    
                    dkEncr.setExternalKey(this.encryptedKeyValue, this.encryptedKeyId);
                    dkEncr.setCustomValueType(WSConstants.SOAPMESSAGE_NS11 + "#"
                            + WSConstants.ENC_KEY_VALUE_TYPE);
                    dkEncr.setSymmetricEncAlgorithm(algorithmSuite.getEncryption());
                    dkEncr.setDerivedKeyLength(algorithmSuite.getEncryptionDerivedKeyLength()/8);
                    dkEncr.prepare(doc);
                    
                    
                    if(this.encrTokenElement != null) {
                        this.encrDKTElement = RampartUtil.insertSiblingAfter(
                                rmd, this.encrTokenElement, dkEncr.getdktElement());
                    } else {
                        this.encrDKTElement = RampartUtil.insertSiblingBefore(
                                rmd, this.sigDKTElement, dkEncr.getdktElement());
                    }
                    
                    refList = dkEncr.encryptForExternalRef(null, encrParts);
                    
                    RampartUtil.insertSiblingAfter(rmd, 
                                                    this.encrDKTElement, 
                                                    refList);
                                                    
                } catch (WSSecurityException e) {
                    throw new RampartException("errorInDKEncr", e);
                } catch (ConversationException e) {
                    throw new RampartException("errorInDKEncr", e);
                }
            } else {
                try {
                    
                    WSSecEncrypt encr = new WSSecEncrypt();
                    
                    RampartUtil.setKeyIdentifierType(rmd, encr, encrToken);
                    
                    encr.setWsConfig(rmd.getConfig());
                    
                    encr.setDocument(doc);
                    RampartUtil.setEncryptionUser(rmd, encr);
                    encr.setSymmetricEncAlgorithm(algorithmSuite.getEncryption());
                    encr.setKeyEncAlgo(algorithmSuite.getAsymmetricKeyWrap());
                    encr.prepare(doc, RampartUtil.getEncryptionCrypto(rpd
                            .getRampartConfig(), rmd.getCustomClassLoader()));
                    
                    if(this.timestampElement != null){
                    	this.setInsertionLocation(this.timestampElement);
                    }else{
                    	this.setInsertionLocation(null);
                    }
                    
                    if(encr.getBSTTokenId() != null) {
                        this.setInsertionLocation(RampartUtil
                                .insertSiblingAfterOrPrepend(rmd,
                                        this.getInsertionLocation(),
                                        encr.getBinarySecurityTokenElement()));
                    }
                    
                    
                    Element encryptedKeyElement = encr.getEncryptedKeyElement();
                                       
                    //Encrypt, get hold of the ref list and add it
                    refList = encr.encryptForInternalRef(null, encrParts);
                    
                    //Add internal refs
                    encryptedKeyElement.appendChild(refList);
                    
                    this.setInsertionLocation(RampartUtil
                            .insertSiblingAfterOrPrepend(rmd,
                                    this.getInsertionLocation(),
                                    encryptedKeyElement)); 

//                    RampartUtil.insertSiblingAfter(rmd,
//                                                    this.getInsertionLocation(),
//                                                    refList);
                } catch (WSSecurityException e) {
                    throw new RampartException("errorInEncryption", e);
                }    
            }
        }
        
        Vector supportingTokens = rpd.getSupportingPolicyData();
        for (int i = 0; i < supportingTokens.size(); i++) {
            SupportingPolicyData policyData = null;
            if (supportingTokens.get(i) != null) {
                policyData = (SupportingPolicyData) supportingTokens.get(i);
                Token supportingEncrToken = policyData.getEncryptionToken();
                Vector supoortingEncrParts = RampartUtil.getSupportingEncryptedParts(rmd,
                        policyData);

                if (supportingEncrToken != null && supoortingEncrParts.size() > 0) {
                    doEncryptionWithSupportingToken(rpd, rmd, supportingEncrToken, doc,
                            supoortingEncrParts);
                }
            }
        }
        
        if(tlog.isDebugEnabled()){
    		t2 = System.currentTimeMillis();
    		tlog.debug("Signature took :" + (t1 - t0)
    				+", Encryption took :" + (t2 - t1) );
    	}
        
    }
    
    private void doSupportingSignature(RampartMessageData rmd, Vector supportingSigParts,
            SupportingPolicyData supportingData) throws RampartException {

        Token supportingSigToken;
        WSSecSignature supportingSig;
        Element supportingSignatureElement;

        long t0 = 0, t1 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }

        supportingSigToken = supportingData.getSignatureToken();

        if (!(supportingSigToken instanceof X509Token)) {
            return;
        }
        supportingSig = this.getSignatureBuilder(rmd, supportingSigToken,
                ((X509Token) supportingSigToken).getUserCertAlias());
        Element bstElem = supportingSig.getBinarySecurityTokenElement();
        if (bstElem != null) {
            bstElem = RampartUtil.insertSiblingAfter(rmd, this.getInsertionLocation(), bstElem);
            this.setInsertionLocation(bstElem);
        }

        if (rmd.getPolicyData().isTokenProtection() && supportingSig.getBSTTokenId() != null) {
            supportingSigParts.add(new WSEncryptionPart(supportingSig.getBSTTokenId()));
        }

        try {
            supportingSig.addReferencesToSign(supportingSigParts, rmd.getSecHeader());
            supportingSig.computeSignature();

            supportingSignatureElement = supportingSig.getSignatureElement();

            this.setInsertionLocation(RampartUtil.insertSiblingAfter(rmd, this
                    .getInsertionLocation(), supportingSignatureElement));

        } catch (WSSecurityException e) {
            throw new RampartException("errorInSignatureWithX509Token", e);
        }

        signatureValues.add(supportingSig.getSignatureValue());

        if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
            tlog.debug("Signature took :" + (t1 - t0));
        }

    }

    private void doSignature(RampartMessageData rmd) throws RampartException {

        RampartPolicyData rpd = rmd.getPolicyData();
        Document doc = rmd.getDocument();
        
        long t0 = 0, t1 = 0;
        if(tlog.isDebugEnabled()){
    		t0 = System.currentTimeMillis();
    	}
        if(rmd.isInitiator()) {
            sigToken = rpd.getInitiatorToken();
        } else {
            sigToken = rpd.getRecipientToken();
        }

        if (sigToken.isDerivedKeys()) {
            // Set up the encrypted key to use
            if(this.encrKey == null) {
                setupEncryptedKey(rmd, sigToken);
            }
            
            WSSecDKSign dkSign = new WSSecDKSign();
            dkSign.setExternalKey(this.encryptedKeyValue, this.encryptedKeyId);

            // Set the algo info
            dkSign.setSignatureAlgorithm(rpd.getAlgorithmSuite()
                    .getSymmetricSignature());
            dkSign.setDerivedKeyLength(rpd.getAlgorithmSuite()
                    .getSignatureDerivedKeyLength() / 8);
            dkSign.setCustomValueType(WSConstants.SOAPMESSAGE_NS11 + "#"
                    + WSConstants.ENC_KEY_VALUE_TYPE);
            try {
                dkSign.prepare(doc, rmd.getSecHeader());

                if (rpd.isTokenProtection()) {
                    sigParts.add(new WSEncryptionPart(encrKey.getId()));
                }

                dkSign.setParts(sigParts);

                dkSign.addReferencesToSign(sigParts, rmd.getSecHeader());

                // Do signature
                dkSign.computeSignature();

                 ;
                // Add elements to header
                 this.sigDKTElement = RampartUtil.insertSiblingAfter(rmd,
                        this.getInsertionLocation(), dkSign.getdktElement());
                this.setInsertionLocation(this.sigDKTElement);
                
                this.setInsertionLocation(RampartUtil.insertSiblingAfter(rmd,
                        this.getInsertionLocation(), dkSign
                                .getSignatureElement()));
                                
                this.mainSigId = RampartUtil
                        .addWsuIdToElement((OMElement) dkSign
                                .getSignatureElement());

                signatureValues.add(dkSign.getSignatureValue());
                
                signatureElement = dkSign.getSignatureElement();
            } catch (WSSecurityException e) {
                throw new RampartException("errorInDerivedKeyTokenSignature", e);
            } catch (ConversationException e) {
                throw new RampartException("errorInDerivedKeyTokenSignature", e);
            }

        } else {
            sig = this.getSignatureBuilder(rmd, sigToken);
            Element bstElem = sig.getBinarySecurityTokenElement();
            if(bstElem != null) {
                bstElem = RampartUtil.insertSiblingAfter(rmd, this
                                        .getInsertionLocation(), bstElem);
                this.setInsertionLocation(bstElem);
            }
            
            if (rmd.getPolicyData().isTokenProtection()
                    && sig.getBSTTokenId() != null) {
                sigParts.add(new WSEncryptionPart(sig.getBSTTokenId()));
            }

            try {
                // set the digest algorithm specified in the security policy
                sig.setDigestAlgo(rpd.getAlgorithmSuite().getDigest());

                sig.addReferencesToSign(sigParts, rmd.getSecHeader());
                sig.computeSignature();

                signatureElement = sig.getSignatureElement();
                
                this.setInsertionLocation(RampartUtil.insertSiblingAfter(
                                rmd, this.getInsertionLocation(), signatureElement));

                this.mainSigId = RampartUtil.addWsuIdToElement((OMElement) signatureElement);
            } catch (WSSecurityException e) {
                throw new RampartException("errorInSignatureWithX509Token", e);
            }
            signatureValues.add(sig.getSignatureValue());
        }
        
        if(tlog.isDebugEnabled()){
    		t1 = System.currentTimeMillis();
    		tlog.debug("Signature took :" + (t1 - t0));
    	}

    }
    
    private void doEncryptionWithSupportingToken(RampartPolicyData rpd, RampartMessageData rmd,
            Token encrToken, Document doc, Vector encrParts) throws RampartException {
        Element refList = null;
        try {
            if (!(encrToken instanceof X509Token)) {
                return;
            }

            WSSecEncrypt encr = new WSSecEncrypt();

            RampartUtil.setKeyIdentifierType(rmd, encr, encrToken);

            encr.setWsConfig(rmd.getConfig());

            encr.setDocument(doc);
            RampartUtil.setEncryptionUser(rmd, encr, ((X509Token) encrToken).getEncryptionUser());
            encr.setSymmetricEncAlgorithm(rpd.getAlgorithmSuite().getEncryption());
            encr.setKeyEncAlgo(rpd.getAlgorithmSuite().getAsymmetricKeyWrap());
            encr.prepare(doc, RampartUtil.getEncryptionCrypto(rpd.getRampartConfig(), rmd
                    .getCustomClassLoader()));

            if (this.timestampElement != null) {
                this.setInsertionLocation(this.timestampElement);
            } else {
                this.setInsertionLocation(null);
            }

            if (encr.getBSTTokenId() != null) {
                this.setInsertionLocation(RampartUtil.insertSiblingAfterOrPrepend(rmd, this
                        .getInsertionLocation(), encr.getBinarySecurityTokenElement()));
            }

            Element encryptedKeyElement = encr.getEncryptedKeyElement();

            // Encrypt, get hold of the ref list and add it
            refList = encr.encryptForInternalRef(null, encrParts);

            // Add internal refs
            encryptedKeyElement.appendChild(refList);

            this.setInsertionLocation(RampartUtil.insertSiblingAfterOrPrepend(rmd, this
                    .getInsertionLocation(), encryptedKeyElement));

        } catch (WSSecurityException e) {
            throw new RampartException("errorInEncryption", e);
        }
    }


    /**
     * @param rmd
     * @throws RampartException
     */
    private void setupEncryptedKey(RampartMessageData rmd, Token token) 
    throws RampartException {
        if(!rmd.isInitiator() && token.isDerivedKeys()) {
                
                //If we already have them, simply return
                if(this.encryptedKeyId != null && this.encryptedKeyValue != null) {
                    return;
                }
                
                //Use the secret from the incoming EncryptedKey element
                Object resultsObj = rmd.getMsgContext().getProperty(WSHandlerConstants.RECV_RESULTS);
                if(resultsObj != null) {
                    encryptedKeyId = RampartUtil.getRequestEncryptedKeyId((Vector)resultsObj);
                    encryptedKeyValue = RampartUtil.getRequestEncryptedKeyValue((Vector)resultsObj);
                    
                    //In the case where we don't have the EncryptedKey in the 
                    //request, for the control to have reached this state,
                    //the scenario MUST be a case where this is the response
                    //message by a listener created for an async client
                    //Therefor we will create a new EncryptedKey
                    if(encryptedKeyId == null && encryptedKeyValue == null) {
                        createEncryptedKey(rmd, token);
                    }
                } else {
                    throw new RampartException("noSecurityResults");
                }
        } else {
            createEncryptedKey(rmd, token);
        }
       
    }

    /**
     * Create an encrypted key element
     * @param rmd
     * @param token
     * @throws RampartException
     */
    private void createEncryptedKey(RampartMessageData rmd, Token token) throws RampartException {
        //Set up the encrypted key to use
        encrKey = this.getEncryptedKeyBuilder(rmd, token);

        Element bstElem = encrKey.getBinarySecurityTokenElement();
        if (bstElem != null) {
            // If a BST is available then use it
            RampartUtil.appendChildToSecHeader(rmd, bstElem);
        }
        
        // Add the EncryptedKey
        encrTokenElement = encrKey.getEncryptedKeyElement();
        this.encrTokenElement = RampartUtil.appendChildToSecHeader(rmd,
                encrTokenElement);
        encryptedKeyValue = encrKey.getEphemeralKey();
        encryptedKeyId = encrKey.getId();

        //Store the token for client - response verification 
        // and server - response creation
        try {
            org.apache.rahas.Token tok = new org.apache.rahas.Token(
                    encryptedKeyId, (OMElement)encrTokenElement , null, null);
            tok.setSecret(encryptedKeyValue);
            rmd.getTokenStorage().add(tok);
        } catch (TrustException e) {
            throw new RampartException("errorInAddingTokenIntoStore", e);
        }
    }
}
