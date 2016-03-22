package org.apache.rahas.impl;

import java.io.ByteArrayOutputStream;
import java.security.Principal;
import java.text.DateFormat;
import java.util.Date;

import javax.xml.stream.XMLStreamException;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.impl.util.SAMLCallbackHandler;
import org.apache.rahas.impl.util.SAMLNameIdentifierCallback;
import org.apache.ws.security.KerberosTokenPrincipal;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.opensaml.Configuration;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLSubject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

public class SAML2PassiveTokenIssuer extends SAML2TokenIssuer {

    private SAMLTokenIssuerConfig config = null;
    private RahasData data = null;
    
    public void setConfig(SAMLTokenIssuerConfig config) {
        this.config = config;
    }
    
    public OMElement issuePassiveRSTR(RahasData data) throws TrustException {

//        DocumentBuilderFactoryImpl.setDOOMRequired(true);
        
        MessageContext inMsgCtx = data.getInMessageContext();
        this.data = data;

        SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx.getEnvelope().getNamespace().getNamespaceURI());

        Crypto crypto;
        if (config.cryptoElement != null) {

            crypto = CryptoFactory.getInstance(TrustUtil.toProperties(config.cryptoElement), inMsgCtx.getAxisService()
                    .getClassLoader());
        } else if (config.cryptoPropertiesElement != null && config.cryptoPropertiesElement.getFirstElement() != null) {
            crypto = CryptoFactory.getInstance(
                    TrustUtil.toProperties(config.cryptoPropertiesElement.getFirstElement()), inMsgCtx.getAxisService()
                            .getClassLoader());
        } else {
            crypto = CryptoFactory.getInstance(config.cryptoPropertiesFile, inMsgCtx.getAxisService().getClassLoader());
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
        Assertion assertion = null;

        assertion = createBearerAssersion(config, doc, crypto, data);

        OMElement rstrcElem = null;
        OMElement rstrElem = null;
        int wstVersion = data.getVersion();
        if (RahasConstants.VERSION_05_02 == wstVersion) {
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(wstVersion, env.getBody());
        } else {
            rstrcElem = TrustUtil.createRequestSecurityTokenResponseCollectionElement(wstVersion, env.getBody());
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(wstVersion, rstrcElem);
        }

        TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(RahasConstants.TOK_TYPE_SAML_20);

        if (config.addRequestedAttachedRef) {
            TrustUtil.createRequestedAttachedRef(wstVersion, rstrElem, "#" + assertion.getID(),
                    RahasConstants.TOK_TYPE_SAML_20);
        }

        if (config.addRequestedUnattachedRef) {
            TrustUtil.createRequestedUnattachedRef(wstVersion, rstrElem, assertion.getID(),
                    RahasConstants.TOK_TYPE_SAML_20);
        }

        if (data.getAppliesToAddress() != null) {
            TrustUtil.createAppliesToElement(rstrElem, data.getAppliesToAddress(), data.getAddressingNs());
        }

        // Use GMT time in milliseconds
        DateFormat zulu = new XmlSchemaDateFormat();

        // Add the Lifetime element
        TrustUtil.createLifetimeElement(wstVersion, rstrElem, zulu.format(creationTime), zulu.format(expirationTime));

        // Create the RequestedSecurityToken element and add the SAML token
        // to it
        OMElement reqSecTokenElem = TrustUtil.createRequestedSecurityTokenElement(wstVersion, rstrElem);
        Token assertionToken;

        Node tempNode = assertion.getDOM();

        // Serializing and re-generating the AXIOM element using the DOM Element created using xerces
        Element element = assertion.getDOM();

        ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();

        DOMImplementationRegistry registry = null;
        try {
            registry = DOMImplementationRegistry.newInstance();
        } catch (ClassNotFoundException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        } catch (InstantiationException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        } catch (IllegalAccessException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        } catch (ClassCastException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        }

        DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");

        LSSerializer writer = impl.createLSSerializer();
        LSOutput output = impl.createLSOutput();
        output.setByteStream(byteArrayOutputStrm);
        writer.write(element, output);
        String elementString = byteArrayOutputStrm.toString();

        OMElement assertionElement = null;
        try {
            assertionElement = AXIOMUtil.stringToOM(elementString);
        } catch (XMLStreamException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        }

        reqSecTokenElem.addChild((OMNode) ((Element) rstrElem).getOwnerDocument().importNode(tempNode, true));

        // Store the token
        assertionToken = new Token(assertion.getID(), (OMElement) assertionElement, creationTime, expirationTime);

        // At this point we definitely have the secret
        // Otherwise it should fail with an exception earlier
        assertionToken.setSecret(data.getEphmeralKey());

        // SAML tokens are enabled for persistence only if token store is not disabled.
        if (!config.isTokenStoreDisabled()) {
            assertionToken.setPersistenceEnabled(true);
            TrustUtil.getTokenStore(inMsgCtx).add(assertionToken);
        }

        if (rstrcElem != null) {
            return rstrcElem;
        }

        return rstrElem;

    }
    
	public void setAudienceRestrictionCondition(String audienceRestriction)
			throws TrustException {
		this.audienceRestriction = audienceRestriction;

	}

    
}
