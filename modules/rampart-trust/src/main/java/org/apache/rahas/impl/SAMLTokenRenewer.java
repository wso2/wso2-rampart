package org.apache.rahas.impl;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Arrays;
import java.util.Date;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TokenRenewer;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class SAMLTokenRenewer implements TokenRenewer {
    
    private String configParamName;

    private OMElement configElement;

    private String configFile;

    public SOAPEnvelope renew(RahasData data) throws TrustException {
        
        // retrieve the message context
        MessageContext inMsgCtx = data.getInMessageContext();
        
        SAMLTokenIssuerConfig config = null;
        if (this.configElement != null) {
            config = new SAMLTokenIssuerConfig(configElement
                            .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
        }

        // Look for the file
        if (config == null && this.configFile != null) {
            config = new SAMLTokenIssuerConfig(this.configFile);
        }

        // Look for the param
        if (config == null && this.configParamName != null) {
            Parameter param = inMsgCtx.getParameter(this.configParamName);
            if (param != null && param.getParameterElement() != null) {
                config = new SAMLTokenIssuerConfig(param
                        .getParameterElement().getFirstChildWithName(
                                SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
            } else {
                throw new TrustException("expectedParameterMissing",
                        new String[] { this.configParamName });
            }
        }

        if (config == null) {
            throw new TrustException("configurationIsNull");
        }
        if(config.isTokenStoreDisabled()){
            throw new TrustException("errorTokenStoreDisabled");
        }
        //initialize and set token persister and config in configuration context.
        if (TokenIssuerUtil.isPersisterConfigured(config)) {
            TokenIssuerUtil.manageTokenPersistenceSettings(config, inMsgCtx);
        }
        // retrieve the list of tokens from the message context
        TokenStorage tkStorage = TrustUtil.getTokenStore(inMsgCtx);

        try {
            // Set the DOM impl to DOOM
            DocumentBuilderFactoryImpl.setDOOMRequired(true);

            // Create envelope
            SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx
                    .getEnvelope().getNamespace().getNamespaceURI());

            // Create RSTR element, with respective version
            OMElement rstrElem;
            int wstVersion = data.getVersion();
            if (RahasConstants.VERSION_05_02 == wstVersion) {
                rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
                        wstVersion, env.getBody());
            } else {
                OMElement rstrcElem = TrustUtil
                        .createRequestSecurityTokenResponseCollectionElement(
                                wstVersion, env.getBody());
                rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
                        wstVersion, rstrcElem);
            }
            
            Crypto crypto;
            if (config.cryptoElement != null) { 
                // crypto props defined as elements
                crypto = CryptoFactory.getInstance(TrustUtil
                        .toProperties(config.cryptoElement), inMsgCtx
                        .getAxisService().getClassLoader());
            } else { 
                // crypto props defined in a properties file
                crypto = CryptoFactory.getInstance(config.cryptoPropertiesFile,
                        inMsgCtx.getAxisService().getClassLoader());
            }

            // Create TokenType element
            TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
                    RahasConstants.TOK_TYPE_SAML_10);
            
            // Creation and expiration times
            Date creationTime = new Date();
            Date expirationTime = new Date();
            expirationTime.setTime(creationTime.getTime() + config.ttl);
            
            // Use GMT time in milliseconds
            DateFormat zulu = new XmlSchemaDateFormat();

            // Add the Lifetime element
            TrustUtil.createLifetimeElement(wstVersion, rstrElem, zulu
                    .format(creationTime), zulu.format(expirationTime));

            // Obtain the token
            Token tk = tkStorage.getToken(data.getTokenId());

            OMElement assertionOMElement = tk.getToken();
            SAMLAssertion samlAssertion = null;

            try {
                samlAssertion = new SAMLAssertion((Element) assertionOMElement);
                samlAssertion.unsign();
                samlAssertion.setNotBefore(creationTime);
                samlAssertion.setNotOnOrAfter(expirationTime);
                
                // sign the assertion
                X509Certificate[] issuerCerts = crypto
                        .getCertificates(config.issuerKeyAlias);

                String sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
                String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
                if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                    sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                }
                java.security.Key issuerPK = crypto.getPrivateKey(
                        config.issuerKeyAlias, config.issuerKeyPassword);
                
                samlAssertion.sign(sigAlgo, issuerPK, Arrays.asList(issuerCerts));
                
                // Create the RequestedSecurityToken element and add the SAML token
                // to it
                OMElement reqSecTokenElem = TrustUtil
                        .createRequestedSecurityTokenElement(wstVersion, rstrElem);
                
                Node tempNode = samlAssertion.toDOM();
                reqSecTokenElem.addChild((OMNode) ((Element) rstrElem)
                        .getOwnerDocument().importNode(tempNode, true));


            } catch (SAMLException e) {
                throw new TrustException("Cannot create SAML Assertion",e);             
            } catch (WSSecurityException e) {
                throw new TrustException("Cannot create SAML Assertion",e);
            } catch (Exception e) {
                throw new TrustException("Cannot create SAML Assertion",e);
            }
            return env;
        } finally {
            DocumentBuilderFactoryImpl.setDOOMRequired(false);
        }

    }

    /**
     * {@inheritDoc}
     */
    public void setConfigurationFile(String configFile) {
        this.configFile = configFile;

    }
    
    /**
     * {@inheritDoc}
     */
    public void setConfigurationElement(OMElement configElement) {
        this.configElement = configElement;
    }

    /**
     * {@inheritDoc}
     */
    public void setConfigurationParamName(String configParamName) {
        this.configParamName = configParamName;
    }


}
