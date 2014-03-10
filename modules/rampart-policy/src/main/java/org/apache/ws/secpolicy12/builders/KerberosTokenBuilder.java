package org.apache.ws.secpolicy12.builders;

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.KerberosToken;

public class KerberosTokenBuilder implements AssertionBuilder {

	/**
	 * 
	 */
	public Assertion build(OMElement element, AssertionBuilderFactory arg1)
			throws IllegalArgumentException {
		KerberosToken kerberosToken = new KerberosToken(SPConstants.SP_V12);

		OMElement policyElement = element.getFirstElement();

		// Process token inclusion
		OMAttribute includeAttr = element.getAttribute(SP12Constants.INCLUDE_TOKEN);

		if (includeAttr != null) {
			int inclusion = SP11Constants.getInclusionFromAttributeValue(includeAttr
					.getAttributeValue());
			kerberosToken.setInclusion(inclusion);
		}

		if (policyElement != null) {
			Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
			policy = (Policy) policy.normalize(false);
			for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
				processAlternative((List) iterator.next(), kerberosToken);
				/*
				 * since there should be only one alternative
				 */
				break;
			}
		}
		return kerberosToken;
	}

	/**
	 * 
	 * @param assertions
	 * @param parent
	 */
	private void processAlternative(List assertions, KerberosToken parent) {
		Assertion assertion;
		QName name;

		for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
			assertion = (Assertion) iterator.next();
			name = assertion.getName();
			if (SP11Constants.REQUIRE_KERBEROS_V5_TOKEN_11.equals(name)) {
				parent.setRequiresKerberosV5Token(true);
			} else if (SP11Constants.REQUIRE_KERBEROS_GSS_V5_TOKEN_11.equals(name)) {
				parent.setRequiresGssKerberosV5Token(true);
			}
		}
	}

	/**
	 * 
	 */
	public QName[] getKnownElements() {
		return new QName[] { SP12Constants.KERBEROS_TOKEN };
	}
}
