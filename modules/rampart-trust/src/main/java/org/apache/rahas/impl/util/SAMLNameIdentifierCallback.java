package org.apache.rahas.impl.util;

import org.apache.rahas.RahasData;
import org.opensaml.saml1.core.NameIdentifier;

/**
 * This is used retrieve data for the SAMLNameIdentifier.
 @@ -12,7 +12,7 @@
 */
public class SAMLNameIdentifierCallback implements SAMLCallback{

	private NameIdentifier nameId = null;
	private String userId = null;
	private RahasData data = null;

	public int getCallbackType(){
		return SAMLCallback.NAME_IDENTIFIER_CALLBACK;
	}

	public NameIdentifier getNameId() {
		return nameId;
	}

	public void setNameId(NameIdentifier nameId) {
		this.nameId = nameId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getUserId() {
		return userId;
	}
	public RahasData getData() {
		return data;
	}

}
