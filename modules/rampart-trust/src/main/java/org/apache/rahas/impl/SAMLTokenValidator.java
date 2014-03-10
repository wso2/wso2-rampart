package org.apache.rahas.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.util.XMLUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TokenValidator;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.saml.SAML2Util;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * Implementation of a SAML Token Validator for the Security Token Service.
 */
public class SAMLTokenValidator implements TokenValidator {

    private static Log log = LogFactory.getLog(SAMLTokenValidator.class);

    private String configFile;
    private OMElement configElement;
    private String configParamName;
    
    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            log.error("SAMLTokenValidatorBootstrapError", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a SOAPEnvelope with the result of the validation.
     * 
     * @param data
     *                the RahasData object, containing information about the
     *                request.
     */
    public SOAPEnvelope validate(RahasData data) throws TrustException {
        // retrieve the message context
        MessageContext inMsgCtx = data.getInMessageContext();

        // retrieve the list of tokens from the message context
        TokenStorage tkStorage = TrustUtil.getTokenStore(inMsgCtx);

        // Create envelope
        SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx.getEnvelope().getNamespace()
                .getNamespaceURI());

        // Create RSTR element, with respective version
        OMElement rstrElem;
        int wstVersion = data.getVersion();
        if (RahasConstants.VERSION_05_02 == wstVersion) {
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(wstVersion,
                    env.getBody());
        } else {
            OMElement rstrcElem = TrustUtil.createRequestSecurityTokenResponseCollectionElement(
                    wstVersion, env.getBody());
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(wstVersion, rstrcElem);
        }

        // Create TokenType element, set to RSTR/Status
        TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
                TrustUtil.getWSTNamespace(wstVersion) + RahasConstants.TOK_TYPE_STATUS);

        // Create Status element
        OMElement statusElement = createMessageElement(wstVersion, rstrElem,
                RahasConstants.LocalNames.STATUS);

        // Obtain the token
        Token tk = tkStorage.getToken(data.getTokenId());

        // create the crypto object and get the issuer's public key
        SAMLTokenIssuerConfig config = getConfig(inMsgCtx);
        Crypto crypto = getCrypto(inMsgCtx, config);
        PublicKey issuerPBKey = getIssuerPublicKey(config, crypto);

        boolean valid = isValid(tk, issuerPBKey, crypto);
        String validityCode;

        if (valid) {
            validityCode = RahasConstants.STATUS_CODE_VALID;
        } else {
            validityCode = RahasConstants.STATUS_CODE_INVALID;
        }

        // Create Code element (inside Status) and set it to the
        // correspondent value
        createMessageElement(wstVersion, statusElement, RahasConstants.LocalNames.CODE).setText(
                TrustUtil.getWSTNamespace(wstVersion) + validityCode);

        return env;
    }

    /**
     * Checks whether the token is valid or not, by verifying the issuer's own
     * signature. If it has been signed by the token issuer, then it is a valid
     * token.
     * 
     * @param token
     *                the token to validate.
     * @return true if the token has been signed by the issuer.
     */
    private boolean isValid(Token token, PublicKey issuerPBKey, Crypto crypto) {
        // extract SAMLAssertion object from token
        OMElement assertionOMElement = token.getToken();
        SAMLAssertion samlAssertion = null;

        if (RahasConstants.TOK_TYPE_SAML_20_NS.equals(assertionOMElement.getQName().getNamespaceURI())) {
            Assertion assertion = null;
            try {
                assertion = buildAssertion(assertionOMElement.toString());
                
                if (assertion.getSignature() != null) {
                    // validate the signature of the SAML token
                    SAML2Util.validateSignature(assertion, crypto);
                }
            } catch (WSSecurityException e) {
                log.error("Could not verify signature", e);
                return false;
            }
            // if there was no exception, then the token is valid
            return true;
        } else {
            try {
                samlAssertion = new SAMLAssertion((Element) assertionOMElement);

                log.info("Verifying token validity...");

                // check if the token has been signed by the issuer.
                samlAssertion.verify(issuerPBKey);

            } catch (SAMLException e) {
                log.error("Could not verify signature", e);
                return false;
            }

            // if there was no exception, then the token is valid
            return true;
        }
    }
    
    private SAMLTokenIssuerConfig getConfig(MessageContext inMsgCtx) {
        SAMLTokenIssuerConfig config = null;
        try {
            if (configElement != null) {
                config = new SAMLTokenIssuerConfig(
                        configElement
                                .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
            }

            // Look for the file
            if ((config == null) && (configFile != null)) {
                config = new SAMLTokenIssuerConfig(configFile);
            }

            // Look for the param
            if ((config == null) && (configParamName != null)) {
                Parameter param = inMsgCtx.getParameter(configParamName);
                if ((param != null) && (param.getParameterElement() != null)) {
                    config = new SAMLTokenIssuerConfig(param.getParameterElement()
                            .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
                } else {
                    throw new TrustException("expectedParameterMissing",
                            new String[] { configParamName });
                }
            }

            if (config == null) {
                throw new TrustException("configurationIsNull");
            }
            if (config.isTokenStoreDisabled()) {
                throw new TrustException("errorTokenStoreDisabled");
            }
            // initialize and set token persister and config in configuration
            // context.
            if (TokenIssuerUtil.isPersisterConfigured(config)) {
                TokenIssuerUtil.manageTokenPersistenceSettings(config, inMsgCtx);
            }

        } catch (Exception e) {
            log.error("Could not build crypto object", e);
        }

        return config;
    }
    
    /**
     * Create crypto object using SAMLTokenIssuer config
     * @param MessageContext inMsgCtx
     * @param SAMLTokenIssuerConfig  config
     * @return Crypto
     */
    private Crypto getCrypto(MessageContext inMsgCtx, SAMLTokenIssuerConfig config) {
        if (config.cryptoElement != null) {
            // crypto props defined as elements
            return CryptoFactory.getInstance(TrustUtil.toProperties(config.cryptoElement), inMsgCtx
                    .getAxisService().getClassLoader());
        } else {
            // crypto props defined in a properties file
            return CryptoFactory.getInstance(config.cryptoPropertiesFile, inMsgCtx.getAxisService()
                    .getClassLoader());
        }
    }
    
    /**
     * Retreive the Issuer's PK
     * 
     * @param SAMLTokenIssuerConfig config
     * @param Crypto crypto
     * @return
     */
    private PublicKey getIssuerPublicKey(SAMLTokenIssuerConfig config, Crypto crypto) {
        PublicKey issuerPBKey = null;

        try {
            issuerPBKey = crypto.getCertificates(config.issuerKeyAlias)[0].getPublicKey();
        } catch (WSSecurityException e) {
            e.printStackTrace();
        }

        return issuerPBKey;
    }
    
    public Assertion buildAssertion(String elem) throws WSSecurityException {
        Assertion samlAssertion;
        try {
            // Unmarshall and build the assertion from the DOM element.
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(elem.trim().getBytes()));
            Element element = document.getDocumentElement();
            
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            samlAssertion = (Assertion) unmarshaller.unmarshall(element);
        } catch (UnmarshallingException e) {
            throw new WSSecurityException(
                    WSSecurityException.FAILURE, "Failure in unmarshelling the assertion", null, e);
        } catch (IOException e) {
            throw new WSSecurityException(
                    WSSecurityException.FAILURE, "Failure in unmarshelling the assertion", null, e);
        } catch (SAXException e) {
            throw new WSSecurityException(
                    WSSecurityException.FAILURE, "Failure in unmarshelling the assertion", null, e);
        } catch (ParserConfigurationException e) {
            throw new WSSecurityException(
                    WSSecurityException.FAILURE, "Failure in unmarshelling the assertion", null, e);
        }

        if (log.isDebugEnabled()) {
            log.debug("SAML2 Token was validated successfully.");
        }
        return samlAssertion;
    }
  
    /**
     * Returns the <wst:Status> element.
     * 
     * @param version
     *                WS-Trust version.
     * @param parent
     *                the parent OMElement.
     */
    private static OMElement createMessageElement(int version,
	    OMElement parent, String elementName) throws TrustException {
	return createOMElement(parent, TrustUtil.getWSTNamespace(version),
		elementName, RahasConstants.WST_PREFIX);
    }

    private static OMElement createOMElement(OMElement parent, String ns,
	    String ln, String prefix) {
	return parent.getOMFactory().createOMElement(new QName(ns, ln, prefix),
		parent);
    }

    // ========================================================================

    /**
     * Set the configuration file of this TokenValidator. <p/> This is the text
     * value of the &lt;configuration-file&gt; element of the
     * token-dispatcher-configuration
     * 
     * @param configFile
     */
    public void setConfigurationFile(String configFile) {
	this.configFile = configFile;
    }

    /**
     * Set the name of the configuration parameter. <p/> If this is used then
     * there must be a <code>org.apache.axis2.description.Parameter</code>
     * object available in the via the messageContext when the
     * <code>TokenValidator</code> is called.
     * 
     * @param configParamName
     * @see org.apache.axis2.description.Parameter
     */
    public void setConfigurationParamName(String configParamName) {
	this.configParamName = configParamName;
    }

    public void setConfigurationElement(OMElement configElement) {
	this.configElement = configElement;
    }
}
