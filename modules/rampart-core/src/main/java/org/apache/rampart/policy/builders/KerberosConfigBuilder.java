package org.apache.rampart.policy.builders;

import java.util.Iterator;
import java.util.Properties;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;

public class KerberosConfigBuilder implements AssertionBuilder {

    /**
     * 
     */
    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        KerberosConfig krbConfig = new KerberosConfig();
        Properties properties = new Properties();
        OMElement childElement;
        OMAttribute name;
        String value;
        String attrName;

        for (Iterator iterator = element.getChildElements(); iterator.hasNext();) {
            childElement = (OMElement) iterator.next();
            QName prop = new QName(RampartConfig.NS, KerberosConfig.PROPERTY_LN);
            if (prop.equals(childElement.getQName())) {
                name = childElement.getAttribute(new QName(KerberosConfig.PROPERTY_NAME_ATTR));
                value = childElement.getText();
                attrName = name.getAttributeValue();
                // TODO: Need to get rid of these system properties.
                if (attrName != null
                        && (attrName.startsWith("java.") || attrName.startsWith("javax."))) {
                    // setting the jsse properties to the vm
                    System.setProperty(attrName.trim(), value.trim());
                }
                properties.put(attrName.trim(), value.trim());
            }
        }
        krbConfig.setProp(properties);
        return krbConfig;
    }

    /**
     * 
     */
    public QName[] getKnownElements() {
        return new QName[] { new QName(RampartConfig.NS, KerberosConfig.KERBEROS_LN) };
    }
}