package org.apache.rahas.impl.util;

import java.util.ArrayList;
import java.util.List;

import org.apache.rahas.RahasData;
import org.opensaml.common.SAMLObject;


@SuppressWarnings({"UnusedDeclaration"})
public class SAMLAttributeCallback implements SAMLCallback{

	private List<SAMLObject> attributes = null;
	private RahasData data = null;

	public SAMLAttributeCallback(RahasData data){
		attributes = new ArrayList<SAMLObject>();
		this.data = data;
	}

	public int getCallbackType(){
		return SAMLCallback.ATTR_CALLBACK;
	}

	/**
	 * Add SAML1 attribute.
	 * @param attribute SAML1 attribute
	 */
	public void addAttributes(org.opensaml.saml1.core.Attribute attribute){
		attributes.add(attribute);
	}

	/**
	 * Overloaded  method to support SAML2
	 * @param attribute SAML2 attribute.
	 */
	public void addAttributes(org.opensaml.saml2.core.Attribute attribute){
		attributes.add(attribute);
	}

	/**
	 * Get the array of SAML2 attributes.
	 * @return SAML2 attribute list.
	 */
	public org.opensaml.saml2.core.Attribute[] getSAML2Attributes(){
		return (org.opensaml.saml2.core.Attribute[])attributes.toArray
				(new org.opensaml.saml2.core.Attribute[attributes.size()]);
	}

	/**
	 * Get SAML2 attribute
	 * @return SAML2 attributes.
	 */
	public org.opensaml.saml1.core.Attribute[] getAttributes(){
		return (org.opensaml.saml1.core.Attribute[])attributes.toArray
				(new org.opensaml.saml1.core.Attribute[attributes.size()]);

	}

	public RahasData getData() {
		return data;
	}
}