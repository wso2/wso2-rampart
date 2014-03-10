package org.apache.rampart.policy.model;

import java.util.Iterator;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.Assertion;
import org.apache.neethi.Constants;
import org.apache.neethi.PolicyComponent;

public class KerberosConfig implements Assertion {
    
    public final static String KERBEROS_LN = RampartConfig.KERBEROS_CONFIG;
    public final static String PROPERTY_LN = "property";
    public final static String PROPERTY_NAME_ATTR = "name";

    public final static String CLIENT_PRINCIPLE_NAME = "client.principal.name";
    public final static String CLIENT_PRINCIPLE_PASSWORD = "client.principal.password";
    public final static String SERVICE_PRINCIPLE_NAME = "service.principal.name";
    public final static String SERVICE_PRINCIPLE_PASSWORD = "service.principal.password";
    public final static String KDC_DES_AES_FACTOR = "kdc.des.aes.factor";

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
        return new QName(RampartConfig.NS, KERBEROS_LN);
    }

    public boolean isOptional() {
        return true;
    }

    public short getType() {
        return Constants.TYPE_ASSERTION;
    }

    public boolean equal(PolicyComponent policyComponent) {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     */
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
            if (key != null && value != null) {
                writer.writeStartElement(RampartConfig.NS, PROPERTY_LN);
                writer.writeAttribute("name", key.trim());
                writer.writeCharacters(value.trim());
                writer.writeEndElement();
            }
        }
    }

}