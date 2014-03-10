package org.apache.rahas.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.impl.util.SAMLAttributeCallback;
import org.apache.rahas.impl.util.SAMLCallbackHandler;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class SAMLPassiveTokenIssuer extends SAMLTokenIssuer {

    private SAMLTokenIssuerConfig config = null;
    private RahasData data = null;
    private Element audienceRestriction = null;
    private static final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

    public void setConfig(SAMLTokenIssuerConfig config) {
        this.config = config;
    }

    public OMElement issuePassiveRSTR(RahasData data) throws TrustException {

        try {
            MessageContext inMsgCtx = data.getInMessageContext();
            this.data = data;

            // Set the DOM impl to DOOM
            DocumentBuilderFactoryImpl.setDOOMRequired(true);

            SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx.getEnvelope().getNamespace()
                                                                    .getNamespaceURI());

            Crypto crypto;
            if (config.cryptoElement != null) { // crypto props
                // defined as
                // elements
                crypto = CryptoFactory.getInstance(TrustUtil.toProperties(config.cryptoElement),
                                                   inMsgCtx.getAxisService().getClassLoader());
            } else if (config.cryptoPropertiesElement != null && config.cryptoPropertiesElement.getFirstElement() != null) { // crypto props
                crypto = CryptoFactory.getInstance(TrustUtil.toProperties(config.cryptoPropertiesElement.getFirstElement()),
                                                   inMsgCtx.getAxisService().getClassLoader());
            } else { // crypto props defined in a properties file
                crypto = CryptoFactory.getInstance(config.cryptoPropertiesFile, inMsgCtx
                        .getAxisService().getClassLoader());
            }

            // Creation and expiration times
            Date creationTime = new Date();
            Date expirationTime = new Date();
            expirationTime.setTime(creationTime.getTime() + config.ttl);

            // Get the document
            Document doc = ((Element) env).getOwnerDocument();

            // Get the key size and create a new byte array of that size
            int keySize = data.getKeysize();

            keySize = (keySize == -1) ? config.keySize : keySize;

            /*
             * We always expect a Bearer assertion
             */

            SAMLAssertion assertion;
            assertion = createBearerAssertion(config, doc, crypto, creationTime, expirationTime,
                                              data);

            OMElement rstrElem = null;
            OMElement rstrcElem = null;
            int wstVersion = data.getVersion();
            if (RahasConstants.VERSION_05_02 == wstVersion) {
                rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(wstVersion, env
                        .getBody());
            } else {
                rstrcElem = TrustUtil.createRequestSecurityTokenResponseCollectionElement(
                        wstVersion, env.getBody());
                rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(wstVersion,
                                                                               rstrcElem);
            }

            TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
                    RahasConstants.TOK_TYPE_SAML_10);

            if (config.addRequestedAttachedRef) {
                createAttachedRef(rstrElem, assertion.getId(), wstVersion);
            }

            if (config.addRequestedUnattachedRef) {
                createUnattachedRef(rstrElem, assertion.getId(), wstVersion);
            }

            if (data.getAppliesToAddress() != null) {
                TrustUtil.createAppliesToElement(rstrElem, data.getAppliesToAddress(), data
                        .getAddressingNs());
            }

            // Use GMT time in milliseconds
            DateFormat zulu = new XmlSchemaDateFormat();

            // Add the Lifetime element
            TrustUtil.createLifetimeElement(wstVersion, rstrElem, zulu.format(creationTime), zulu
                    .format(expirationTime));

            // Create the RequestedSecurityToken element and add the SAML token
            // to it
            OMElement reqSecTokenElem = TrustUtil.createRequestedSecurityTokenElement(wstVersion,
                                                                                      rstrElem);
            Token assertionToken;
            try {
                Node tempNode = assertion.toDOM();
                reqSecTokenElem.addChild((OMNode) ((Element) rstrElem).getOwnerDocument()
                        .importNode(tempNode, true));

                // Store the token
                assertionToken = new Token(assertion.getId(), (OMElement) assertion.toDOM(),
                                           creationTime, expirationTime);

                // At this point we definitely have the secret
                // Otherwise it should fail with an exception earlier
                assertionToken.setSecret(data.getEphmeralKey());
                TrustUtil.getTokenStore(inMsgCtx).add(assertionToken);

            } catch (SAMLException e) {
                throw new TrustException("samlConverstionError", e);
            }

            if (rstrcElem != null) {
                return rstrcElem;
            }

            return rstrElem;
        } finally {
            // Unset the DOM impl to default
            DocumentBuilderFactoryImpl.setDOOMRequired(false);
        }

    }

    protected SAMLAssertion createAuthAssertion(Document doc, String confMethod,
                                                SAMLNameIdentifier subjectNameId,
                                                Element keyInfoContent,
                                                SAMLTokenIssuerConfig config,
                                                Crypto crypto, Date notBefore, Date notAfter,
                                                String actAs) throws TrustException {
        try {
            String[] confirmationMethods = new String[]{confMethod};

            Element keyInfoElem = null;
            if (keyInfoContent != null) {
                keyInfoElem = doc.createElementNS(WSConstants.SIG_NS, "KeyInfo");
                ((OMElement) keyInfoContent).declareNamespace(WSConstants.SIG_NS,
                                                              WSConstants.SIG_PREFIX);
                ((OMElement) keyInfoContent).declareNamespace(WSConstants.ENC_NS,
                                                              WSConstants.ENC_PREFIX);

                keyInfoElem.appendChild(keyInfoContent);
            }

            SAMLSubject subject = new SAMLSubject(subjectNameId,
                                                  Arrays.asList(confirmationMethods), null, keyInfoElem);

            List statements = new ArrayList();

            SAMLAttribute[] attrs = null;
            if (config.getCallbackHander() != null) {
                SAMLAttributeCallback cb = new SAMLAttributeCallback(data);
                SAMLCallbackHandler handler = config.getCallbackHander();
                handler.handle(cb);
                attrs = cb.getAttributes();
            } else if (config.getCallbackHandlerName() != null
                       && config.getCallbackHandlerName().trim().length() > 0) {
                SAMLAttributeCallback cb = new SAMLAttributeCallback(data);
                SAMLCallbackHandler handler = null;
                MessageContext msgContext = data.getInMessageContext();
                ClassLoader classLoader = msgContext.getAxisService().getClassLoader();
                Class cbClass = null;
                try {
                    cbClass = Loader.loadClass(classLoader, config.getCallbackHandlerName());
                } catch (ClassNotFoundException e) {
                    throw new TrustException("cannotLoadPWCBClass", new String[]{config
                                                                                         .getCallbackHandlerName()}, e);
                }
                try {
                    handler = (SAMLCallbackHandler) cbClass.newInstance();
                } catch (java.lang.Exception e) {
                    throw new TrustException("cannotCreatePWCBInstance", new String[]{config
                                                                                              .getCallbackHandlerName()}, e);
                }
                handler.handle(cb);
                attrs = cb.getAttributes();
            } else {
                // TODO Remove this after discussing
                SAMLAttribute attribute = new SAMLAttribute("Name",
                                                            "https://rahas.apache.org/saml/attrns", null, -1, Arrays
                        .asList(new String[]{"Colombo/Rahas"}));
                attrs = new SAMLAttribute[]{attribute};
            }
            List<SAMLAttribute> attributeList = Arrays.asList(attrs);

            // If ActAs is present in the RST
            if (data.getActAs() != null) {
                SAMLAttribute actAsAttribute = new SAMLAttribute("ActAs",
                                                                 "https://rahas.apache.org/saml/attrns", null, -1, Arrays
                        .asList(new String[]{data.getActAs()}));
                attributeList.add(actAsAttribute);
            }

            SAMLAttributeStatement attrStmt = new SAMLAttributeStatement(subject, attributeList);
            statements.add(attrStmt);

            List conditions = null;

            if (audienceRestriction != null) {
                SAMLCondition condition = SAMLCondition.getInstance(audienceRestriction);
                conditions = new ArrayList();
                conditions.add(condition);
            }

            SAMLAssertion assertion = new SAMLAssertion(config.issuerName, notBefore, notAfter,
                                                        conditions, null, statements);

            // sign the assertion
            X509Certificate[] issuerCerts = crypto.getCertificates(config.issuerKeyAlias);

            String sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
            String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
            if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
            }
            java.security.Key issuerPK = crypto.getPrivateKey(config.issuerKeyAlias,
                                                              config.issuerKeyPassword);
            assertion.sign(sigAlgo, issuerPK, Arrays.asList(issuerCerts));

            return assertion;
        } catch (Exception e) {
            throw new TrustException("samlAssertionCreationError", e);
        }
    }

    public void setAudienceRestrictionCondition(String uri) throws TrustException {
        String audienceRestrictionXmlString = "<saml1:AudienceRestrictionCondition xmlns:saml1=\"urn:oasis:names:tc:SAML:1.0:assertion\"><saml1:Audience>" +
                                              uri + "</saml1:Audience></saml1:AudienceRestrictionCondition>";

        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document =
                    builder.parse(new InputSource(new StringReader(audienceRestrictionXmlString)));
            this.audienceRestriction = document.getDocumentElement();
        } catch (Exception e) {
            throw new TrustException("samlAssertionCreationError");
        }
    }

}
