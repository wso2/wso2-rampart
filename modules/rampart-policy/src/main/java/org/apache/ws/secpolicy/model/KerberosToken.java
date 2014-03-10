package org.apache.ws.secpolicy.model;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.ws.secpolicy.Constants;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class KerberosToken extends Token {

	private boolean requiresKerberosV5Token;

	private boolean requiresGssKerberosV5Token;

	private String tokenVersionAndType = Constants.WSS_KERBEROS_TOKEN11;

	public String getTokenVersionAndType() {
		return tokenVersionAndType;
	}

	public void setTokenVersionAndType(String tokenVersionAndType) {
		this.tokenVersionAndType = tokenVersionAndType;
	}

	public boolean isRequiresKerberosV5Token() {
		return requiresKerberosV5Token;
	}

	public void setRequiresKerberosV5Token(boolean requiresKerberosV5Token) {
		this.requiresKerberosV5Token = requiresKerberosV5Token;
	}

	public boolean isRequiresGssKerberosV5Token() {
		return requiresGssKerberosV5Token;
	}

	public void setRequiresGssKerberosV5Token(boolean requiresGssKerberosV5Token) {
		this.requiresGssKerberosV5Token = requiresGssKerberosV5Token;
	}

	public KerberosToken(int version) {
		setVersion(version);
	}

	public QName getName() {
		if (version == SPConstants.SP_V12) {
			return SP12Constants.KERBEROS_TOKEN;
		} else {
			return SP11Constants.KERBEROS_TOKEN;
		}
	}

	public void serialize(XMLStreamWriter writer) throws XMLStreamException {
		String localName = getName().getLocalPart();
		String namespaceURI = getName().getNamespaceURI();

		String prefix = writer.getPrefix(namespaceURI);

		if (prefix == null) {
			prefix = getName().getPrefix();
			writer.setPrefix(prefix, namespaceURI);
		}

		// <sp:KerberosToken>
		writer.writeStartElement(prefix, localName, namespaceURI);

		String inclusion;

		if (version == SPConstants.SP_V12) {
			inclusion = SP12Constants
					.getAttributeValueFromInclusion(getInclusion());
		} else {
			inclusion = SP11Constants
					.getAttributeValueFromInclusion(getInclusion());
		}

		if (inclusion != null) {
			writer.writeAttribute(prefix, namespaceURI,
					SPConstants.ATTR_INCLUDE_TOKEN, inclusion);
		}

		String pPrefix = writer.getPrefix(SPConstants.POLICY.getNamespaceURI());
		if (pPrefix == null) {
			pPrefix = SPConstants.POLICY.getPrefix();
			writer.setPrefix(pPrefix, SPConstants.POLICY.getNamespaceURI());
		}

		// <wsp:Policy>
		writer.writeStartElement(pPrefix, SPConstants.POLICY.getLocalPart(),
				SPConstants.POLICY.getNamespaceURI());

		if (isRequiresKerberosV5Token()) {
			// <sp:RequireKeyIdentifierReference />
			writer.writeStartElement(prefix,
					SPConstants.REQUIRE_KERBEROS_V5_TOKEN_11, namespaceURI);
			writer.writeEndElement();
		}

		if (isRequiresGssKerberosV5Token()) {
			// <sp:RequireIssuerSerialReference />
			writer.writeStartElement(prefix,
					SPConstants.REQUIRE_KERBEROS_GSS_V5_TOKEN_11, namespaceURI);
			writer.writeEndElement();
		}

		// </wsp:Policy>
		writer.writeEndElement();

		// </sp:KerberosToken>
		writer.writeEndElement();
	}
}
