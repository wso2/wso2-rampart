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

import com.sun.org.apache.xerces.internal.impl.Constants;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.impl.dom.DOOMAbstractFactory;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.impl.AbstractIssuerConfig;
import org.apache.xerces.util.SecurityManager;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

public class TrustUtil {

    private static final QName NAME = new QName("name");
    private static final int ENTITY_EXPANSION_LIMIT = 0;
    private static final Log logger = LogFactory.getLog(TrustUtil.class);

    /**
     * Create a wsse:Reference element with the given URI and the value type
     *
     * @param doc
     * @param refUri
     * @param refValueType
     * @return Element
     */
    public static Element createSecurityTokenReference(Document doc,
                                                       String refUri, String refValueType) {

        Reference ref = new Reference(doc);
        ref.setURI(refUri);
        if (refValueType != null) {
            ref.setValueType(refValueType);
        }
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.setReference(ref);

        return str.getElement();
    }

    public static Element createSecurityTokenReferenceWithTokenType(Document doc, String refUri, String refValueType,
                                                                    String tokenType) {

        Reference ref = new Reference(doc);
        ref.setURI("#" + refUri);
        if (refValueType != null) {
            ref.setValueType(refValueType);
        }

        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.setReference(ref);

        Element securityTokenReference = str.getElement();
        securityTokenReference.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:wsse11",
                "http://docs.oasis-open.org/wss/oasis-wsswssecurity-secext-1.1.xsd");
        securityTokenReference.setAttributeNS("http://docs.oasis-open" +
                ".org/wss/oasis-wsswssecurity-secext-1.1.xsd", "wsse11:TokenType", tokenType);

        return securityTokenReference;
    }

    public static OMElement
            createRequestSecurityTokenResponseElement(int version,
                                                      OMElement parent) throws TrustException {
        return createOMElement(parent,
                               getWSTNamespace(version),
                               RahasConstants.LocalNames.REQUEST_SECURITY_TOKEN_RESPONSE,
                               RahasConstants.WST_PREFIX);
    }

    public static OMElement
            createRequestSecurityTokenResponseCollectionElement(int version,
                                                                OMElement parent) throws TrustException {
        String ns = getWSTNamespace(version);
        return createOMElement(parent, ns,
                               RahasConstants.LocalNames.
                                       REQUEST_SECURITY_TOKEN_RESPONSE_COLLECTION,
                               RahasConstants.WST_PREFIX);
    }

    public static OMElement createRequestedSecurityTokenElement(
            int version, OMElement parent) throws TrustException {
        String ns = getWSTNamespace(version);
        return createOMElement(parent, ns,
                               RahasConstants.IssuanceBindingLocalNames.REQUESTED_SECURITY_TOKEN,
                               RahasConstants.WST_PREFIX);
    }

    public static OMElement createRequestSecurityTokenElement(int version) throws TrustException {
        String ns = getWSTNamespace(version);
        OMFactory fac = OMAbstractFactory.getOMFactory();
        return fac.
                createOMElement(RahasConstants.LocalNames.REQUEST_SECURITY_TOKEN,
                                ns,
                                RahasConstants.WST_PREFIX);
    }

    public static OMElement createRequestedProofTokenElement(
            int version, OMElement parent) throws TrustException {
        String ns = getWSTNamespace(version);
        return createOMElement(parent, ns,
                               RahasConstants.LocalNames.REQUESTED_PROOF_TOKEN,
                               RahasConstants.WST_PREFIX);
    }

    public static OMElement createEntropyElement(
            int version, OMElement parent) throws TrustException {
        String ns = getWSTNamespace(version);
        return createOMElement(parent, ns,
                               RahasConstants.IssuanceBindingLocalNames.ENTROPY,
                               RahasConstants.WST_PREFIX);
    }

    public static OMElement createComputedKeyElement(int version,
                                                     OMElement parent) throws TrustException {
        return createOMElement(parent,
                               getWSTNamespace(version),
                               RahasConstants.IssuanceBindingLocalNames.COMPUTED_KEY,
                               RahasConstants.WST_PREFIX);
    }

    public static OMElement createRequestTypeElement(int version,
                                                     OMElement parent,
                                                     String value) throws TrustException {
        String ns = getWSTNamespace(version);

        OMElement elem = createOMElement(parent,
                                         ns,
                                         RahasConstants.LocalNames.REQUEST_TYPE,
                                         RahasConstants.WST_PREFIX);

        if (RahasConstants.REQ_TYPE_ISSUE.equals(value)
            || RahasConstants.REQ_TYPE_CANCEL.equals(value)
            || RahasConstants.REQ_TYPE_RENEW.equals(value)
            || RahasConstants.REQ_TYPE_VALIDATE.equals(value)) {
            elem.setText(getWSTNamespaceForRSTRequestTye(version) + value);
        } else {
            elem.setText(value);
        }

        return elem;
    }

    public static OMElement createTokenTypeElement(int version,
                                                   OMElement parent) throws TrustException {
        return createOMElement(parent,
                               getWSTNamespace(version),
                               RahasConstants.LocalNames.TOKEN_TYPE,
                               RahasConstants.WST_PREFIX);
    }
    
    public static OMElement createValidateTargetElement(int version, OMElement parent, 
                                                    OMElement str) throws TrustException {
        OMElement validateTarget = createOMElement(parent,
                getWSTNamespace(version),
                RahasConstants.LocalNames.VALIDATE_TARGET,
                RahasConstants.WST_PREFIX);
        validateTarget.addChild(str);
        
        return validateTarget;
        
    }
    
    public static OMElement createRenewTargetElement(int version, OMElement parent, 
            OMElement str) throws TrustException {
        OMElement renewTarget = createOMElement(parent,
        getWSTNamespace(version),
        RahasConstants.LocalNames.RENEW_TARGET,
        RahasConstants.WST_PREFIX);
        renewTarget.addChild(str);

     return renewTarget;

}
    
    

    public static OMElement createBinarySecretElement(
            int version,
            OMElement parent,
            String type) throws TrustException {
        String ns = getWSTNamespace(version);
        OMElement elem = createOMElement(parent, ns,
                                         RahasConstants.LocalNames.BINARY_SECRET,
                                         RahasConstants.WST_PREFIX);
        if (type != null) {
            elem.addAttribute(elem.getOMFactory().createOMAttribute(
                    RahasConstants.ATTR_TYPE, null, ns + type));
        }
        return elem;
    }

    public static OMElement createComputedKeyAlgorithm(int version,
                                                       OMElement parent,
                                                       String algoId) throws TrustException {
        String ns = getWSTNamespace(version);
        OMElement elem = createOMElement(parent,
                                         ns,
                                         RahasConstants.IssuanceBindingLocalNames.COMPUTED_KEY_ALGO,
                                         RahasConstants.WST_PREFIX);
        elem.setText(ns + algoId);
        return elem;
    }

    public static OMElement
            createRequestedUnattachedRef(int version,
                                         OMElement parent,
                                         String refUri,
                                         String refValueType) throws TrustException {
        String ns = getWSTNamespace(version);
        OMElement elem = createOMElement(parent, ns,
                                         RahasConstants.IssuanceBindingLocalNames.
                                                 REQUESTED_UNATTACHED_REFERENCE,
                                         RahasConstants.WST_PREFIX);
        elem.addChild((OMElement) createSecurityTokenReference(
                ((Element) parent).getOwnerDocument(), refUri, refValueType));
        return elem;
    }

    public static OMElement createRequestedAttachedRef(int version,
                                                       OMElement parent,
                                                       String refUri,
                                                       String refValueType) throws TrustException {
        String ns = getWSTNamespace(version);
        OMElement elem = createOMElement(parent, ns,
                                         RahasConstants.IssuanceBindingLocalNames.
                                                 REQUESTED_ATTACHED_REFERENCE,
                                         RahasConstants.WST_PREFIX);
        elem.addChild((OMElement) createSecurityTokenReference(
                ((Element) parent).getOwnerDocument(), refUri, refValueType));
        return elem;
    }
    
    /**
	 * Create and add wst:AttachedReference element
	 * 
	 * @param rstrElem
	 *            wst:RequestSecurityToken element
	 * @param id
	 *            Token identifier
	 * @throws TrustException
	 */
    public static void createRequestedAttachedRef(OMElement rstrElem, String id, int version)
			throws TrustException {
		OMFactory fac = null;
		OMElement rar = null;
		OMElement str = null;
		OMElement ki = null;

		String ns = TrustUtil.getWSTNamespace(version);
		fac = rstrElem.getOMFactory();
		rar = fac.createOMElement(new QName(ns,
				RahasConstants.IssuanceBindingLocalNames.REQUESTED_ATTACHED_REFERENCE,
				RahasConstants.WST_PREFIX), rstrElem);
		str = fac.createOMElement(new QName(WSConstants.WSSE_NS,
				SecurityTokenReference.SECURITY_TOKEN_REFERENCE, WSConstants.WSSE_PREFIX), rar);
		ki = fac.createOMElement(new QName(WSConstants.WSSE_NS, "KeyIdentifier",
				WSConstants.WSSE_PREFIX), str);
		ki.addAttribute("ValueType", WSConstants.WSS_SAML_KI_VALUE_TYPE, null);
		ki.setText(id);
	}

	/**
	 * Create and add wst:UnattachedReference element
	 * 
	 * @param rstrElem
	 *            wst:RequestSecurityToken element
	 * @param id
	 *            Token identifier
	 * @throws TrustException
	 */
	public static void createRequestedUnattachedRef(OMElement rstrElem, String id, int version)
			throws TrustException {
		OMFactory fac = null;
		OMElement rar = null;
		OMElement str = null;
		OMElement ki = null;

		String ns = TrustUtil.getWSTNamespace(version);
		fac = rstrElem.getOMFactory();
		rar = fac.createOMElement(new QName(ns,
				RahasConstants.IssuanceBindingLocalNames.REQUESTED_UNATTACHED_REFERENCE,
				RahasConstants.WST_PREFIX), rstrElem);
		str = fac.createOMElement(new QName(WSConstants.WSSE_NS,
				SecurityTokenReference.SECURITY_TOKEN_REFERENCE, WSConstants.WSSE_PREFIX), rar);
		ki = fac.createOMElement(new QName(WSConstants.WSSE_NS, "KeyIdentifier",
				WSConstants.WSSE_PREFIX), str);

		ki.addAttribute("ValueType", WSConstants.WSS_SAML_KI_VALUE_TYPE, null);
		ki.setText(id);
	}

    public static OMElement createKeySizeElement(int version,
                                                 OMElement parent,
                                                 int size) throws TrustException {
        String ns = getWSTNamespace(version);
        OMElement ksElem = createOMElement(parent, ns,
                                           RahasConstants.IssuanceBindingLocalNames.KEY_SIZE,
                                           RahasConstants.WST_PREFIX);
        ksElem.setText(Integer.toString(size));
        return ksElem;
    }

    public static OMElement createKeyTypeElement(int version,
                                                 OMElement parent,
                                                 String type) throws TrustException {
        String ns = getWSTNamespace(version);
        OMElement ktElem = createOMElement(parent, ns,
                                           RahasConstants.IssuanceBindingLocalNames.KEY_TYPE,
                                           RahasConstants.WST_PREFIX);
        if (RahasConstants.KEY_TYPE_BEARER.equals(type) ||
            RahasConstants.KEY_TYPE_PUBLIC_KEY.equals(type) ||
            RahasConstants.KEY_TYPE_SYMM_KEY.equals(type)) {
            ktElem.setText(ns + type);
        } else {
            ktElem.setText(type);
        }
        return ktElem;
    }

    public static OMElement
            createRequestedTokenCanceledElement(int version,
                                                OMElement parent) throws TrustException {
        return createOMElement(parent,
                               getWSTNamespace(version),
                               RahasConstants.CancelBindingLocalNames.REQUESTED_TOKEN_CANCELED,
                               RahasConstants.WST_PREFIX);
    }

    public static OMElement createLifetimeElement(int version,
                                                  OMElement parent,
                                                  String created,
                                                  String expires) throws TrustException {

        String ns = getWSTNamespace(version);

        OMElement ltElem = createOMElement(parent, ns,
                                           RahasConstants.IssuanceBindingLocalNames.LIFETIME,
                                           RahasConstants.WST_PREFIX);

        OMElement createdElem = createOMElement(ltElem, WSConstants.WSU_NS,
                                                WSConstants.CREATED_LN,
                                                WSConstants.WSU_PREFIX);
        createdElem.setText(created);

        OMElement expiresElem = createOMElement(ltElem, WSConstants.WSU_NS,
                                                WSConstants.EXPIRES_LN,
                                                WSConstants.WSU_PREFIX);
        expiresElem.setText(expires);

        return ltElem;
    }

    public static OMElement createLifetimeElement(int version,
                                                  OMElement parent,
                                                  long ttl) throws TrustException {

        Date creationTime = new Date();
        Date expirationTime = new Date();
        expirationTime.setTime(creationTime.getTime() + ttl);

        DateFormat zulu = new XmlSchemaDateFormat();

        return createLifetimeElement(version,
                                     parent,
                                     zulu.format(creationTime),
                                     zulu.format(expirationTime));
    }

    public static OMElement createAppliesToElement(OMElement parent,
                                                   String address, String addressingNs) {
        OMElement appliesToElem = createOMElement(parent,
                                                  RahasConstants.WSP_NS,
                                                  RahasConstants.IssuanceBindingLocalNames.
                                                          APPLIES_TO,
                                                  RahasConstants.WSP_PREFIX);

        OMElement eprElem = createOMElement(appliesToElem,
                                            addressingNs,
                                            "EndpointReference",
                                            AddressingConstants.WSA_DEFAULT_PREFIX);
        OMElement addressElem = createOMElement(eprElem, addressingNs,
                                                AddressingConstants.EPR_ADDRESS,
                                                AddressingConstants.WSA_DEFAULT_PREFIX);
        addressElem.setText(address);

        return appliesToElem;
    }

    public static String getActionValue(int version, String action) throws TrustException {
        if (RahasConstants.RST_ACTION_ISSUE.equals(action) ||
            RahasConstants.RST_ACTION_CANCEL.equals(action) ||
            RahasConstants.RST_ACTION_RENEW.equals(action) ||
            RahasConstants.RST_ACTION_VALIDATE.equals(action) ||
            RahasConstants.RST_ACTION_SCT.equals(action) ||
            RahasConstants.RSTR_ACTION_ISSUE.equals(action) ||
            RahasConstants.RSTR_ACTION_CANCEL.equals(action) ||
            RahasConstants.RSTR_ACTION_RENEW.equals(action) ||
            RahasConstants.RSTR_ACTION_VALIDATE.equals(action) ||
            RahasConstants.RSTR_ACTION_SCT.equals(action) ||
            RahasConstants.RSTRC_ACTION_ISSUE_FINAL.equals(action)) {

            return getWSTNamespaceForRSTRequestTye(version) + action;
        }
        return action;
    }

    /**
     * Create a new <code>SOAPEnvelope</code> of the same version as the
     * SOAPEnvelope in the given <code>MessageContext</code>
     *
     * @param nsUri
     * @return SOAPEnvelope
     */
    public static SOAPEnvelope createSOAPEnvelope(String nsUri) {
        if (nsUri != null
            && SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI.equals(nsUri)) {
            return DOOMAbstractFactory.getSOAP11Factory().getDefaultEnvelope();
        } else {
            return DOOMAbstractFactory.getSOAP12Factory().getDefaultEnvelope();
        }
    }


    private static OMElement createOMElement(OMElement parent,
                                             String ns,
                                             String ln,
                                             String prefix) {
        return parent.getOMFactory().createOMElement(new QName(ns, ln, prefix),
                                                     parent);
    }

    public static String getWSTNamespace(int version) throws TrustException {
        switch (version) {
            case RahasConstants.VERSION_05_02:
                return RahasConstants.WST_NS_05_02;
            case RahasConstants.VERSION_05_12:
                return RahasConstants.WST_NS_05_12;
            case RahasConstants.VERSION_08_02:
                return RahasConstants.WST_NS_08_02;
            default:
                throw new TrustException("unsupportedWSTVersion");
        }
    }

    public static int getWSTVersion(String ns) throws TrustException {
        if (RahasConstants.WST_NS_05_02.equals(ns)) {
            return RahasConstants.VERSION_05_02;
        } else if (RahasConstants.WST_NS_05_12.equals(ns)) {
            return RahasConstants.VERSION_05_12;
        } else if(RahasConstants.WST_NS_08_02.equals(ns)){
            return RahasConstants.VERSION_08_02;            
        } else {
            throw new TrustException("unsupportedWSTVersion");
        }
    }

    /**
     * Returns the token store.
     * If the token store is already available in the configuration context then
     * fetch it and return it. If not create a new one, hook it up in the
     * configuration context and return it
     *
     * @param msgCtx
     * @return the token store
     */
    public static TokenStorage getTokenStore(MessageContext msgCtx) {
        ConfigurationContext configCtx = msgCtx.getConfigurationContext();
        return getTokenStore(configCtx);
    }
    
    /**
     * Fetches the token storage from the configuration context.
     * If the token store is already available in the configuration context then
     * fetch it and return it. If not create a new one, hook it up in the
     * configuration context and return it
     * @param ctx
     * @return
     */
    public static TokenStorage getTokenStore(ConfigurationContext ctx) {
        TokenStorage storage = (TokenStorage) ctx
                .getProperty(TokenStorage.TOKEN_STORAGE_KEY);
        if (storage == null) {
            storage = new SimpleTokenStore();
            ctx.setProperty(TokenStorage.TOKEN_STORAGE_KEY, storage);
        }
        return storage;
    }

    /**
     * Create an ephemeral key
     *
     * @return The generated ephemeral key
     * @throws TrustException
     */
    protected byte[] generateEphemeralKey(int keySize) throws TrustException {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] temp = new byte[keySize / 8];
            random.nextBytes(temp);
            return temp;
        } catch (Exception e) {
            throw new TrustException("Error in creating the ephemeral key", e);
        }
    }

    /**
     * Create an ephemeral key
     *
     * @return The generated ephemeral key
     * @throws TrustException
     */
    protected byte[] generateEphemeralKey(byte[] reqEnt,
                                          byte[] respEnt,
                                          String algo,
                                          int keySize) throws TrustException {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] temp = new byte[keySize / 8];
            random.nextBytes(temp);
            return temp;
        } catch (Exception e) {
            throw new TrustException("Error in creating the ephemeral key", e);
        }
    }

    public static OMElement createCancelTargetElement(int version,
                                                      OMElement parent) throws TrustException {
        return createOMElement(parent,
                               getWSTNamespace(version),
                               RahasConstants.CancelBindingLocalNames.CANCEL_TARGET,
                               RahasConstants.WST_PREFIX);

    }
    
    public static OMElement createClaims(int version, 
    											OMElement parent, String dialect) throws TrustException{
        OMElement omElem = createOMElement(parent,
                getWSTNamespace(version),
                RahasConstants.IssuanceBindingLocalNames.CLAIMS,
                RahasConstants.WST_PREFIX);    	
        
        OMNamespace ns = omElem.getOMFactory().createOMNamespace(getWSTNamespace(version), 
        		RahasConstants.WSP_PREFIX);
        omElem.addAttribute(RahasConstants.ATTR_CLAIMS_DIALECT , dialect, ns);
       
        
        return omElem;
    }
    


    public static OMElement createCancelRequest(String tokenId,
                                                int version) throws TrustException {
        /*
       <wst:RequestSecurityToken>
            <wst:RequestType>
            http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel
            </wst:RequestType>
            <wst:CancelTarget>
                    <o:SecurityTokenReference
                         xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                      <o:Reference URI="urn:uuid:8e6a3a95-fd1b-4c24-96d4-28e875025ff7"
                                   ValueType="http://schemas.xmlsoap.org/ws/2005/02/sc/sct" />
                    </o:SecurityTokenReference>
            </wst:CancelTarget>
        </wst:RequestSecurityToken>
        */
        OMElement rst = TrustUtil.createRequestSecurityTokenElement(version);
        TrustUtil.createRequestTypeElement(version, rst, RahasConstants.REQ_TYPE_CANCEL);
        OMElement cancelTargetEle = TrustUtil.createCancelTargetElement(version, rst);
        OMFactory factory = rst.getOMFactory();
        OMElement secTokenRefEle =
                factory.createOMElement(SecurityTokenReference.SECURITY_TOKEN_REFERENCE,
                                        WSConstants.WSSE_NS,
                                        WSConstants.WSSE_PREFIX);
        OMElement refEle =
                factory.createOMElement(Reference.TOKEN);
        refEle.addAttribute(factory.createOMAttribute(RahasConstants.CancelBindingLocalNames.URI,
                                                      null, tokenId));
        secTokenRefEle.addChild(refEle);
        cancelTargetEle.addChild(secTokenRefEle);

        return rst;
    }

    public static Properties toProperties(OMElement cryptoElem) {
        Properties properties = new Properties();

        /*
           Process an element similar to this;

                <crypto provider="org.apache.ws.security.components.crypto.Merlin">
                    <property name="org.apache.ws.security.crypto.merlin.keystore.type">jks</property>
                    <property name="org.apache.ws.security.crypto.merlin.file">sts.jks</property>
                    <property name="org.apache.ws.security.crypto.merlin.keystore.password">password</property>
                </crypto>
        */
        for (Iterator propIter = cryptoElem.getChildElements(); propIter.hasNext();) {
            OMElement propElem = (OMElement) propIter.next();
            String name = propElem.getAttribute(NAME).getAttributeValue().trim();
            String value = propElem.getText().trim();
            properties.setProperty(name, value);
        }
        properties.setProperty("org.apache.ws.security.crypto.provider",
                cryptoElem.getAttribute(AbstractIssuerConfig.PROVIDER)
                        .getAttributeValue().trim());
        return properties;
    }

    /**
     * Get the subject confirmation method of a SAML 2.0 assertion
     * @param assertion SAML 2.0 assertion
     * @return  Subject Confirmation method
     */
    public static String getSAML2SubjectConfirmationMethod(Assertion assertion){
        String subjectConfirmationMethod = RahasConstants.SAML20_SUBJECT_CONFIRMATION_HOK;
        List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        if(subjectConfirmations.size() > 0){
            subjectConfirmationMethod = subjectConfirmations.get(0).getMethod();
        }
        return  subjectConfirmationMethod;
    }

     /**
     * This method is intended to provide the correct RST Request type provided the WS-Trust version. It defines Reqeust
     * Types and WSA:Actions related to WS-Trust using the http://docs.oasis-open.org/ws-sx/ws-trust/200512 namespace.
     * @param version
     * @return Correct version
     */
    public static String getWSTNamespaceForRSTRequestTye(int version) throws TrustException {
        switch (version) {
            case RahasConstants.VERSION_05_02:
                return RahasConstants.WST_NS_05_02;
            case RahasConstants.VERSION_05_12:
                return RahasConstants.WST_NS_05_12;
            //In this case, we are returning the value, "http://docs.oasis-open.org/ws-sx/ws-trust/200512" as
            // the namespace as per the WS-Trust 1.4 specification.
            case RahasConstants.VERSION_08_02:
                return RahasConstants.WST_NS_05_02;
            default:
                throw new TrustException("unsupportedWSTVersion");
        }
    }

    /**
     * This method is used to create and add the "ActAs" element into a RST as per the wS-Trust 1.4 specification. This
     * ActAs element contains a SAML Token as the child.
     * @param parent
     * @param version
     * @param samlToken
     * @return
     * @throws TrustException
     */
    public static OMElement createActAsElement(OMElement parent, int version, OMElement samlToken) throws TrustException{
        if(version < 3){
            throw new TrustException("ActAs element is not supported in this trust version.");
        }

        OMElement actAsElem = createOMElement(parent, getWSTNamespace(version), RahasConstants.LocalNames.ACTAS,
                RahasConstants.WST_PREFIX);
        if(samlToken != null){
            actAsElem.addChild(samlToken);
        }
        else{
            throw new TrustException("The child element of the ActAs element should not be null");
        }
        return actAsElem;
    }

    /**
     * Create DocumentBuilderFactory with the XXE and XEE prevention measurements
     *
     * @return DocumentBuilderFactory instance
     */
    public static DocumentBuilderFactory getSecuredDocumentBuilderFactory() {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        try {
            dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE, false);
            dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE, false);
            dbf.setFeature(Constants.XERCES_FEATURE_PREFIX + Constants.LOAD_EXTERNAL_DTD_FEATURE, false);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (ParserConfigurationException e) {
            logger.error(
                    "Failed to load XML Processor Feature " + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE + " or " +
                    Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE + " or " + Constants.LOAD_EXTERNAL_DTD_FEATURE +
                    "or secure-processing.");
        }

        SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
        dbf.setAttribute(Constants.XERCES_PROPERTY_PREFIX + Constants.SECURITY_MANAGER_PROPERTY, securityManager);

        return dbf;
    }


    /**
     *  Check whether we need to set a DOOMBuilderFactory based parser pool for the OpenSAML library
     *  DOOMBuilderFactory based parser pool was required to overcome the concurrency issue between STS ans SAML
     *  when used in the same JVM. We are enabling this fix by default.
     *
     * @return
     */
    public static boolean isDoomParserPoolUsed() {
        String doomParserPoolSwitch = System.getProperty(RahasConstants.AXIOM_PARSE_POOL_ENABLED_PROPERTY);
        boolean doomParserPoolEnabled = true; // we are enabling this fix by default

        if (StringUtils.isNotBlank(doomParserPoolSwitch) && !Boolean.parseBoolean(doomParserPoolSwitch)) {
            doomParserPoolEnabled = false;
        }

        return doomParserPoolEnabled;
    }
    
}
