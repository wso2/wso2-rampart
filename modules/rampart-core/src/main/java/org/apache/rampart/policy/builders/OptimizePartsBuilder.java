/*
 * Copyright 2001-2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.rampart.policy.builders;

import java.util.Iterator;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.rampart.policy.model.OptimizePartsConfig;
import org.apache.rampart.policy.model.RampartConfig;

/**
 * OptimizePartsBuilder creates the OptimizePartsConfig
 * 
 * This clase deserialize the following XML fragment inside the RampartConfig.
 * Example
<pre>
&lt;ramp:optimizeParts&gt;<br />
&lt;ramp:expressions&gt;<br />
&lt;ramp:expression&gt;//ns1:data1&lt;/ramp:expression&gt;<br />
&lt;ramp:expression&gt;//ns2:data2&lt;/ramp:expression&gt;<br />
&lt;/ramp:expressions&gt;<br />
&nbsp;&lt;ramp:namespaces&gt;<br />
&lt;nampespace uri="http://test1.com" prefix="ns1"/&gt;<br />
&lt;nampespace uri="http://test2.com" prefix="ns2"/&gt;<br />
&lt;/ramp:namespaces&gt;<br />
&lt;/ramp:optimizeParts&gt;
</pre>
 * @see OptimizePartsConfig
 */
public class OptimizePartsBuilder implements AssertionBuilder{

	public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
		OptimizePartsConfig assertion = new OptimizePartsConfig();
		OMElement expressionsElem = element.getFirstChildWithName(new QName(RampartConfig.NS, OptimizePartsConfig.EXPRESSIONS_LN));
		
		if(expressionsElem != null){
			Iterator iterator = expressionsElem.getChildElements();
			while(iterator.hasNext()){
				OMElement elem = (OMElement)iterator.next();
				String expression = elem.getText();
				assertion.addExpression(expression);
			}
			
		}
		
		OMElement nsElem = element.getFirstChildWithName(new QName(RampartConfig.NS, OptimizePartsConfig.NAMESPACES_LN));
		if(nsElem != null){
			Iterator iterator = nsElem.getChildElements();
			while(iterator.hasNext()){
				OMElement elem = (OMElement)iterator.next();
				String namespace = elem.getText();
				String prefix = elem.getAttributeValue(new QName("", OptimizePartsConfig.PREFIX_ATTR));
				String uri = elem.getAttributeValue(new QName("", OptimizePartsConfig.URI_ATTR));
				assertion.addNamespaces(prefix, uri);
			}
			
		}
		return assertion;
	}

	public QName[] getKnownElements() {
		return new QName[] {new QName(RampartConfig.NS, OptimizePartsConfig.OPTIMIZE_PARTS_LN)};
	}
	
}
