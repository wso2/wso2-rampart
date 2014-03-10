package org.apache.rampart.policy.model;

import java.util.Iterator;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.Assertion;
import org.apache.neethi.Constants;
import org.apache.neethi.PolicyComponent;

public class SSLConfig implements Assertion{
	public final static String SSL_LN = RampartConfig.SSL_CONFIG;
	public final static String PROPERTY_LN = "property";
	public final static String PROPERTY_NAME_ATTR = "name";
	
	private Properties prop;
	
	public Properties getProp() {
        return prop;
    }
    public void setProp(Properties prop) {
        this.prop = prop;
    }
	
	public PolicyComponent normalize() {
        // TODO TODO
        throw new UnsupportedOperationException("TODO");
    }
	
	public QName getName() {
        return new QName(RampartConfig.NS, SSL_LN);
    }

    public boolean isOptional() {
        // TODO TODO
        throw new UnsupportedOperationException("TODO");
    }
    
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String prefix = writer.getPrefix(RampartConfig.NS);
        
        if (prefix == null) {
            prefix = RampartConfig.NS;
            writer.setPrefix(prefix, RampartConfig.NS);
        }                
        
        String key;
        String value;
        
        for (Iterator iterator = prop.keySet().iterator(); iterator.hasNext();) {
            key = (String) iterator.next();
            value = prop.getProperty(key);
            writer.writeStartElement(RampartConfig.NS, PROPERTY_LN);

            writer.writeAttribute("name", key);

            writer.writeCharacters(value);
            writer.writeEndElement();
        }
        
        writer.writeEndElement();
    }
    
    public short getType() {
        return Constants.TYPE_ASSERTION;
    }
    
    public boolean equal(PolicyComponent policyComponent) {
        throw new UnsupportedOperationException();
    }
    
}
