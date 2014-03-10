package org.apache.rampart.policy;

import java.util.Iterator;

import org.apache.ws.secpolicy.model.Header;
import org.apache.ws.secpolicy.model.SupportingToken;

public class SupportingPolicyData extends RampartPolicyData {

	public void build(SupportingToken token) {

		if (token.getSignedParts() != null && !token.getSignedParts().isOptional()) {
			Iterator it = token.getSignedParts().getHeaders().iterator();
			this.setSignBody(token.getSignedParts().isBody());
			while (it.hasNext()) {
				Header header = (Header) it.next();
				this.addSignedPart(header.getNamespace(), header.getName());
			}
		}

		if (token.getEncryptedParts() != null && !token.getEncryptedParts().isOptional()) {
			Iterator it = token.getEncryptedParts().getHeaders().iterator();
			this.setEncryptBody(token.getEncryptedParts().isBody());
			while (it.hasNext()) {
				Header header = (Header) it.next();
				this.setEncryptedParts(header.getNamespace(), header.getName(),
						"Header");
			}
		}

		if (token.getSignedElements() != null && !token.getSignedElements().isOptional()) {
			Iterator it = token.getSignedElements().getXPathExpressions()
					.iterator();
			while (it.hasNext()) {
				this.setSignedElements((String) it.next());
			}
			this.addDeclaredNamespaces(token.getSignedElements()
					.getDeclaredNamespaces());
		}

		if (token.getEncryptedElements() != null && !token.getEncryptedElements().isOptional()) {
			Iterator it = token.getEncryptedElements().getXPathExpressions()
					.iterator();
			while (it.hasNext()) {
				this.setEncryptedElements((String) it.next());
			}
			if (token.getSignedElements() == null) {
				this.addDeclaredNamespaces(token.getEncryptedElements()
						.getDeclaredNamespaces());
			}
		}
	}
}
