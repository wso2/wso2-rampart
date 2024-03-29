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

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.neethi.Policy;
import org.apache.rampart.handler.config.InflowConfiguration;
import org.apache.rampart.handler.config.OutflowConfiguration;
import org.apache.ws.secpolicy.SP11Constants;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.List;

/**
 *
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class RahasSAML2TokenUTForBearerTest extends TestClient {

    public RahasSAML2TokenUTForBearerTest(String name) {
        super(name);
    }

    public OMElement getRequest() {
        try {
            OMElement rstElem = TrustUtil.createRequestSecurityTokenElement(RahasConstants.VERSION_05_02);
            TrustUtil.createRequestTypeElement(RahasConstants.VERSION_05_02, rstElem, RahasConstants.REQ_TYPE_ISSUE);
            OMElement tokenTypeElem = TrustUtil.createTokenTypeElement(RahasConstants.VERSION_05_02, rstElem);
            tokenTypeElem.setText(RahasConstants.TOK_TYPE_SAML_20);

            TrustUtil.createAppliesToElement(rstElem, "http://localhost:5555/axis2/services/SecureService", this.getWSANamespace());
            TrustUtil.createKeyTypeElement(RahasConstants.VERSION_05_02,
                    rstElem, RahasConstants.KEY_TYPE_BEARER);
            TrustUtil.createKeySizeElement(RahasConstants.VERSION_05_02, rstElem, 256);

            return rstElem;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public OutflowConfiguration getClientOutflowConfiguration() {
        OutflowConfiguration ofc = new OutflowConfiguration();

        ofc.setActionItems("UsernameToken Timestamp");
        ofc.setUser("joe");
        ofc.setPasswordCallbackClass(PWCallback.class.getName());
        return ofc;
    }

    public InflowConfiguration getClientInflowConfiguration() {
        InflowConfiguration ifc = new InflowConfiguration();

        ifc.setActionItems("Timestamp");

        return ifc;
    }

    public String getServiceRepo() {
        return "rahas_service_repo_3";
    }

    public String getRequestAction() throws TrustException {
        return TrustUtil.getActionValue(RahasConstants.VERSION_05_02, RahasConstants.RST_ACTION_ISSUE);
    }

    public void validateRsponse(OMElement resp) {
        OMElement rst = resp.getFirstChildWithName(new QName(RahasConstants.WST_NS_05_02,
                                                             RahasConstants.IssuanceBindingLocalNames.
                                                                     REQUESTED_SECURITY_TOKEN));
        assertNotNull("RequestedSecurityToken missing", rst);

        OMElement elem = rst.getFirstChildWithName(new QName(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion"));
        assertNotNull("Missing SAML Assertion", elem);

        Assertion assertion = getAssertionObjectFromOMElement(elem);
        Subject subject = assertion.getSubject();
        assertNotNull("SAML Subject of the assertion cannot be null", subject);

        List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
        assertNotNull("At least one Subject Confirmation should be present in the SAML Subject",
                      subjectConfirmations.get(0));
        assertEquals("Subject Confirmation should be BEARER : urn:oasis:names:tc:SAML:2.0:cm:bearer",
                         RahasConstants.SAML20_SUBJECT_CONFIRMATION_BEARER,
                         subjectConfirmations.get(0).getMethod());
    }

    /* (non-Javadoc)
     * @see org.apache.rahas.TestClient#getServicePolicy()
     */
    public Policy getServicePolicy() throws Exception {
        return this.getPolicy("test-resources/rahas/policy/service-policy-transport-binding.xml");
    }

    /* (non-Javadoc)
     * @see org.apache.rahas.TestClient#getSTSPolicy()
     */
    public Policy getSTSPolicy() throws Exception {
        return this.getPolicy("test-resources/rahas/policy/sts-policy-transport-binding.xml");
    }

    /* (non-Javadoc)
     * @see org.apache.rahas.TestClient#getRSTTemplate()
     */
    public OMElement getRSTTemplate() throws TrustException {
        OMFactory factory = OMAbstractFactory.getOMFactory();
        OMElement elem = factory.createOMElement(SP11Constants.REQUEST_SECURITY_TOKEN_TEMPLATE);

        TrustUtil.createTokenTypeElement(
                RahasConstants.VERSION_05_02, elem).setText(RahasConstants.TOK_TYPE_SAML_20);
        TrustUtil.createKeyTypeElement(
                RahasConstants.VERSION_05_02, elem, RahasConstants.KEY_TYPE_BEARER);

        return elem;
    }

    public int getTrstVersion() {
        return RahasConstants.VERSION_05_02;
    }

    /**
     * Build the SAML Assertion object from the OMElement for the ease of processing
     * @param omElement OMElement containing the SAML Assertion
     * @return Assertion object
     */
    private Assertion getAssertionObjectFromOMElement(OMElement omElement){
        Assertion assertion = null;
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(omElement.toString().getBytes()));
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport
                    .getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory
                    .getUnmarshaller(element);
            assertion = (org.opensaml.saml.saml2.core.Assertion) unmarshaller
                    .unmarshall(element);
        } catch (Exception e){
            e.printStackTrace();
        }
        return  assertion;
    }
}
