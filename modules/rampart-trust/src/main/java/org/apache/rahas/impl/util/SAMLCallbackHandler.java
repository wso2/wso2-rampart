package org.apache.rahas.impl.util;

import org.opensaml.SAMLException;

/**
 * SAMLCallback Handler enables you to add data to the
 * to the SAMLAssertion.
 * 
 * For example Assertions, NameIdentifiers.
 * 
 */
public interface SAMLCallbackHandler {

	/**
	 * SAMLCallback object has indicates what kind of data is required.
	 * if(callback.getCallbackType() == SAMLCallback.ATTR_CALLBACK)
	 * {
	 * 		SAMLAttributeCallback attrCallback = (SAMLAttributeCallback)callback;
	 * 		\//Retrieve required data from the RahasData inside SAMLAttributeCallback 
	 * 		\//Add your SAMLAttributes to the attrCallback here.
	 * 		
	 * }
	 * @param callback
	 * @throws SAMLException
	 */
	public void handle(SAMLCallback callback) throws SAMLException;

}
