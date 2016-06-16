package org.apache.rahas.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.rahas.*;
import org.apache.rahas.impl.util.SignKeyHolder;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
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

public class SAML2TokenRenewer extends SAMLTokenRenewer implements TokenRenewer {

    protected List<Signature> signatureList = new ArrayList<Signature>();

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

        // Change to DOM implementation if DOOM was switched on
        if (DocumentBuilderFactoryImpl.isDOOMRequired()) {
            DocumentBuilderFactoryImpl.setDOOMRequired(false);
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
            String sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
            String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
            if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
            }
            java.security.Key issuerPK = crypto.getPrivateKey(
                    config.issuerKeyAlias, config.issuerKeyPassword);

            signKeyHolder.setIssuerCerts(issuerCerts);
            signKeyHolder.setIssuerPK((PrivateKey) issuerPK);
            signKeyHolder.setSignatureAlgorithm(sigAlgo);

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
}
