package org.apache.rahas.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.*;
import org.apache.rahas.impl.util.SAMLUtils;
import org.apache.rahas.impl.util.SignKeyHolder;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.*;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class SAML2TokenRenewer implements TokenRenewer {

    private String configParamName;

    private OMElement configElement;

    private String configFile;

    protected List<Signature> signatureList = new ArrayList<Signature>();

    private static final Log log = LogFactory.getLog(SAML2TokenRenewer.class);

    public SOAPEnvelope renew(RahasData data) throws TrustException {

        MessageContext inMsgCtx = data.getInMessageContext();
        // retrieve the list of tokens from the message context
        TokenStorage tkStorage = TrustUtil.getTokenStore(inMsgCtx);
        SAMLTokenIssuerConfig config = setConfig(inMsgCtx);
        // Create envelope
        SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx
                .getEnvelope().getNamespace().getNamespaceURI());
        // Create RSTR element for SAML 2.0
        OMElement rstrElem = buildResponse(inMsgCtx, data, env, RahasConstants.TOK_TYPE_SAML_20);
        int wstVersion = data.getVersion();

        // Creation and expiration times
        Date creationTime = new Date();
        Date expirationTime = new Date();
        expirationTime.setTime(creationTime.getTime() + config.ttl);

        // Use GMT time in millisecondscreationTime
        DateFormat zulu = new XmlSchemaDateFormat();
        // Add the Lifetime element
        TrustUtil.createLifetimeElement(wstVersion, rstrElem, zulu
                .format(creationTime), zulu.format(expirationTime));
        // Obtain the token
        Token tk = tkStorage.getToken(data.getTokenId());
        OMElement assertionOMElement = tk.getToken();

        if (!TrustUtil.isDoomParserPoolUsed()) {
            // Change to DOM implementation if DOOM was switched on
            if (DocumentBuilderFactoryImpl.isDOOMRequired()) {
                DocumentBuilderFactoryImpl.setDOOMRequired(false);
            }
        }
        String s = assertionOMElement.toString();
        DocumentBuilderFactory documentBuilderFactory = TrustUtil.getSecuredDocumentBuilderFactory();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = null;

        try {
            Crypto crypto = getCrypto(inMsgCtx, config);
            docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(s.trim().getBytes()));
            Element element = document.getDocumentElement();
            // Unmarshall the DOMElement to build the assertion
            DefaultBootstrap.bootstrap();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            Assertion samlAssertion = (Assertion) unmarshaller.unmarshall(element);

            DateTime creationDate = new DateTime();
            DateTime expirationDate = new DateTime(creationDate.getMillis() + config.ttl);
            // set conditions for
            Conditions conditions = new ConditionsBuilder().buildObject();
            conditions.setNotBefore(creationDate);
            conditions.setNotOnOrAfter(expirationDate);
            samlAssertion.setConditions(conditions);

            SignKeyHolder signKeyHolder = createSignKeyHolder(config, crypto);
            Assertion signedAssertion = signAssertion(samlAssertion, signKeyHolder);
            // Create the RequestedSecurityToken element and add the SAML token to it
            OMElement reqSecTokenElem = TrustUtil
                    .createRequestedSecurityTokenElement(wstVersion, rstrElem);
            Node tempNode = signedAssertion.getDOM();
            reqSecTokenElem.addChild((OMNode) ((Element) rstrElem)
                    .getOwnerDocument().importNode(tempNode, true));
        } catch (ParserConfigurationException e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        } catch (SAXException e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        } catch (UnmarshallingException e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        } catch (ConfigurationException e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        } catch (IOException e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        }
        return env;
    }

    /**
     * set the signKeyHolder (Similar to credential)
     *
     * @param config
     * @param crypto
     * @return
     * @throws TrustException
     */
    private SignKeyHolder createSignKeyHolder(SAMLTokenIssuerConfig config, Crypto crypto) throws TrustException {
        SignKeyHolder signKeyHolder = new SignKeyHolder();
        try {
            X509Certificate[] issuerCerts = crypto
                    .getCertificates(config.issuerKeyAlias);
            String sigAlgo = SAMLUtils.getSignatureAlgorithm(config, issuerCerts);
            String digestAlgorithm = SAMLUtils.getDigestAlgorithm(config);
            java.security.Key issuerPK = crypto.getPrivateKey(
                    config.issuerKeyAlias, config.issuerKeyPassword);

            signKeyHolder.setIssuerCerts(issuerCerts);
            signKeyHolder.setIssuerPK((PrivateKey) issuerPK);
            signKeyHolder.setSignatureAlgorithm(sigAlgo);
            signKeyHolder.setDigestAlgorithm(digestAlgorithm);

        } catch (WSSecurityException e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        } catch (Exception e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        }
        return signKeyHolder;
    }

    /**
     * Sign the SAML 2.0 assertion using signKeyHolder and set the keyInfo
     *
     * @param assertion
     * @param cred
     * @return
     */
    private Assertion signAssertion(Assertion assertion, SignKeyHolder cred) throws TrustException {

        // Build the signature object and set the credentials.
        Signature signature = (Signature) Configuration.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(cred);
        signature.setSignatureAlgorithm(cred.getSignatureAlgorithm());
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSigningCredential(cred);
        try {
            KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
            org.opensaml.xml.signature.X509Certificate cert = (org.opensaml.xml.signature.X509Certificate) buildXMLObject(org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
            String value = org.apache.xml.security.utils.Base64.encode(cred.getEntityCertificate().getEncoded());
            cert.setValue(value);
            data.getX509Certificates().add(cert);
            keyInfo.getX509Datas().add(data);
            signature.setKeyInfo(keyInfo);
            assertion.setSignature(signature);
            String digestAlgorithm = cred.getDigestAlgorithm();
            if (StringUtils.isNotBlank(digestAlgorithm) && signature.getContentReferences() != null &&
                    !signature.getContentReferences().isEmpty()) {
                ((SAMLObjectContentReference)signature.getContentReferences().get(0))
                        .setDigestAlgorithm(digestAlgorithm);
                if (log.isDebugEnabled()) {
                    log.debug("Selected '" + digestAlgorithm + "' as the digest algorithm.");
                }
            }
            signatureList.add(signature);
            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
            Element assertionElem = marshaller.marshall(assertion);
            org.apache.xml.security.Init.init();
            Signer.signObjects(signatureList);
        } catch (MarshallingException e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        } catch (Exception e) {
            throw new TrustException("Cannot create SAML 2.0 Assertion", e);
        }
        return assertion;
    }

    /**
     * This method is used to build the assertion elements
     *
     * @param objectQName
     * @return
     * @throws Exception
     */
    protected static XMLObject buildXMLObject(QName objectQName) throws Exception {
        XMLObjectBuilder builder = org.opensaml.xml.Configuration.getBuilderFactory().getBuilder(objectQName);
        if (builder == null) {
            throw new TrustException("Unable to retrieve builder for object QName "
                    + objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
                objectQName.getPrefix());
    }

    /**
     * set the configuration for SAML 1.1 and 2.0 renewing
     * @param inMsgCtx
     * @return
     * @throws TrustException
     */
    protected SAMLTokenIssuerConfig  setConfig(MessageContext inMsgCtx) throws TrustException {
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
        return config;
    }

    /**
     * create the RSTR element with the token type
     * @param inMsgCtx
     * @param data
     * @param env
     * @param tokenType
     * @return
     * @throws TrustException
     */
    protected OMElement buildResponse(MessageContext inMsgCtx, RahasData data, SOAPEnvelope env, String tokenType) throws TrustException {
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
        // Create TokenType element
        TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
                tokenType);
        return rstrElem;
    }

    /**
     * create the crypto from configuration. Used in SAML2tokenRenewer as well
     * @param inMsgCtx
     * @param config
     * @return
     */
    protected Crypto getCrypto(MessageContext inMsgCtx, SAMLTokenIssuerConfig config){
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
        return crypto;
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
