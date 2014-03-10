package org.apache.rahas;

import java.util.Arrays;

import org.apache.rahas.impl.util.SAMLAttributeCallback;
import org.apache.rahas.impl.util.SAMLCallback;
import org.apache.rahas.impl.util.SAMLCallbackHandler;
import org.apache.rahas.impl.util.SAMLNameIdentifierCallback;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;

public class SAMLDataProvider implements SAMLCallbackHandler{
	
	public void handle(SAMLCallback callback) throws SAMLException{
		
		if(callback.getCallbackType() == SAMLCallback.ATTR_CALLBACK){
			SAMLAttributeCallback cb = (SAMLAttributeCallback)callback;
			SAMLAttribute attribute = new SAMLAttribute("Name",
                     "https://rahas.apache.org/saml/attrns", null, -1, Arrays
                             .asList(new String[] { "Custom/Rahas" }));
			cb.addAttributes(attribute);
		}else if(callback.getCallbackType() == SAMLCallback.NAME_IDENTIFIER_CALLBACK){
			SAMLNameIdentifierCallback cb = (SAMLNameIdentifierCallback)callback;
			SAMLNameIdentifier nameId = new SAMLNameIdentifier(
            		"David", null, SAMLNameIdentifier.FORMAT_EMAIL);
			cb.setNameId(nameId);
		}
		
	}
}
