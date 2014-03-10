/*
 * Copyright 2001-2004 The Apache Software Foundation.
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
package org.apache.ws.secpolicy12.builders;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.model.IssuedToken;

import javax.xml.namespace.QName;

import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class IssuedTokenBuilder implements AssertionBuilder {

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {
        IssuedToken issuedToken = new IssuedToken(SPConstants.SP_V12);

        OMAttribute  includeAttr = element.getAttribute(SP12Constants.INCLUDE_TOKEN);
        if(includeAttr != null) {
            int inclusion = SP12Constants.getInclusionFromAttributeValue(includeAttr.getAttributeValue());
            issuedToken.setInclusion(inclusion);
        }
        // Extract Issuer
        OMElement issuerElem = element.getFirstChildWithName(SP12Constants.ISSUER);
       
        if(issuerElem != null) {
            OMElement issuerEpr = issuerElem.getFirstChildWithName(new QName(AddressingConstants.Final.WSA_NAMESPACE,"Address"));
            
            //try the other addressing namespace
            if (issuerEpr == null) {
                issuerEpr = issuerElem.getFirstChildWithName(new QName(AddressingConstants.Submission.WSA_NAMESPACE,"Address"));
            }
            
            issuedToken.setIssuerEpr(issuerEpr);
        }
        
        //TODO check why this returns an Address element
        //iter = issuerElem.getChildrenWithLocalName("Metadata");
        
        if (issuerElem != null ) {
            OMElement issuerMex = issuerElem.getFirstChildWithName(new QName(AddressingConstants.Final.WSA_NAMESPACE,"Metadata"));
            
          //try the other addressing namespace
            if (issuerMex == null) {
                issuerMex = issuerElem.getFirstChildWithName(new QName(AddressingConstants.Submission.WSA_NAMESPACE,"Metadata"));
            }
                        
            issuedToken.setIssuerMex(issuerMex);
        }

// Extract RSTTemplate
        OMElement rstTmplElem = element.getFirstChildWithName(SP12Constants.REQUEST_SECURITY_TOKEN_TEMPLATE);
        if (rstTmplElem != null) {
            issuedToken.setRstTemplate(rstTmplElem);
            // Process the RST Template and extract the token type
            Iterator<OMElement> tokenTypeElems = rstTmplElem.getChildrenWithName(
                    SP12Constants.REQUEST_SECURITY_TOKEN_TEMPLATE_TOKEN_TYPE);
            if(tokenTypeElems != null && tokenTypeElems.hasNext()){
                issuedToken.setRstTokenType(tokenTypeElems.next().getText());
            }

            // Process the RST Template and extract the Claim set
            Iterator<OMElement> claimsElemIterator = rstTmplElem.getChildrenWithName(
                    SP12Constants.REQUEST_SECURITY_TOKEN_TEMPLATE_CLAIMS);

            Set<String> claimSet = new TreeSet<String>() ;
            if (claimsElemIterator != null && claimsElemIterator.hasNext()) {
                OMElement claimsElem = claimsElemIterator.next();
                if(claimsElem != null && claimsElem.getChildrenWithName(
                            SP12Constants.REQUEST_SECURITY_TOKEN_TEMPLATE_CLAIM_TYPE) != null){
                    for(Iterator<OMElement> claims = claimsElem.getChildrenWithName(
                            SP12Constants.REQUEST_SECURITY_TOKEN_TEMPLATE_CLAIM_TYPE); claims.hasNext();){
                        OMElement claim = claims.next();
                        // exclude the claims with the attribute Optional=true
                        if(!(claim.getAttribute(
                                SP12Constants.ATTR_RST_TEMPLATE_CLAIM_TYPE_OPTIONAL) != null &&
                           "true".equals(claim.getAttribute(
                                SP12Constants.ATTR_RST_TEMPLATE_CLAIM_TYPE_OPTIONAL).getAttributeValue()))){
                            claimSet.add(claim.getAttributeValue(
                                SP12Constants.ATTR_RST_TEMPLATE_CLAIM_TYPE_URI));
                        }
                    }
                }
            }
            issuedToken.setRstClaimSet(claimSet);
        }


        OMElement policyElement = element.getFirstChildWithName(org.apache.neethi.Constants.Q_ELEM_POLICY);

        if (policyElement != null) {

            Policy policy = PolicyEngine.getPolicy(policyElement);
            policy = (Policy) policy.normalize(false);

            for (Iterator iterator = policy.getAlternatives(); iterator
                    .hasNext();) {
                processAlternative((List) iterator.next(), issuedToken);
                break; // since there should be only one alternative ..
            }
        }

        return issuedToken;
    }

    public QName[] getKnownElements() {
        return new QName[] { SP12Constants.ISSUED_TOKEN };
    }

    private void processAlternative(List assertions, IssuedToken parent) {
        Assertion assertion;
        QName name;

        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            assertion = (Assertion) iterator.next();
            name = assertion.getName();

            if (SP12Constants.REQUIRE_DERIVED_KEYS.equals(name)) {
                parent.setDerivedKeys(true);
            } else if (SP12Constants.REQUIRE_EXTERNAL_REFERNCE.equals(name)) {
                parent.setRequireExternalReference(true);
            } else if (SP12Constants.REQUIRE_INTERNAL_REFERNCE.equals(name)) {
                parent.setRequireInternalReference(true);
            }
        }

    }
}
