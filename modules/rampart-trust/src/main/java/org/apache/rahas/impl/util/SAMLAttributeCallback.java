package org.apache.rahas.impl.util;

import java.util.ArrayList;
import java.util.List;

import org.apache.rahas.RahasData;
import org.opensaml.SAMLAttribute;
import org.opensaml.saml2.core.Attribute;

public class SAMLAttributeCallback implements SAMLCallback{
	
	private List attributes = null;
	private RahasData data = null;
	
	public SAMLAttributeCallback(RahasData data){
		attributes = new ArrayList();
		this.data = data;
	}
	
	public int getCallbackType(){
		return SAMLCallback.ATTR_CALLBACK;
	}
	
	public void addAttributes(SAMLAttribute attribute){
		attributes.add(attribute);
	}

    /**
     * Overloaded  method to support SAML2
     * @param attr
     */
    public void addAttributes(Attribute attr){
        attributes.add(attr);
    }

    /**
     * Get the array of SAML2 attributes.
     * @return
     */
    public Attribute[] getSAML2Attributes(){
        return (Attribute[])attributes.toArray(new Attribute[attributes.size()]);
    }
	
	public SAMLAttribute[] getAttributes(){
		return (SAMLAttribute[])attributes.toArray(new SAMLAttribute[attributes.size()]);
		
	}

	public RahasData getData() {
		return data;
	}

}
