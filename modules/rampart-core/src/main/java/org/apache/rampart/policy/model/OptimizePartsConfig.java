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

package org.apache.rampart.policy.model;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.Assertion;
import org.apache.neethi.Constants;
import org.apache.neethi.PolicyComponent;


public class OptimizePartsConfig implements Assertion{

	public final static String OPTIMIZE_PARTS_LN = RampartConfig.OPTIMISE_PARTS;
	public final static String EXPRESSIONS_LN = "expressions";
	public final static String EXPRESSION_LN = "expression";
	public final static String NAMESPACES_LN = "namespaces";
	public final static String NAMESPACE_LN = "namespace";
	public final static String URI_ATTR = "uri";
	public final static String PREFIX_ATTR = "prefix";
	
	private Map namespaces = null;
	private Vector expressions = null;
	
	public OptimizePartsConfig(){
		namespaces = new HashMap();
		expressions = new Vector();
	}
	
	public void addExpression(String expression){
		expressions.add(expression);
	}
	
	public void addNamespaces(String prefix, String ns){
		namespaces.put(prefix, ns);
	}
	
	public Vector getExpressions() {
		return expressions;
	}

	public Map getNamespaces() {
		return namespaces;
	}
	
	public short getType() {
        return Constants.TYPE_ASSERTION;
	}
	
	public QName getName() {
		return new QName(RampartConfig.NS, OPTIMIZE_PARTS_LN);
	}
	
	public void serialize(XMLStreamWriter writer) throws XMLStreamException {
		String prefix = writer.getPrefix(RampartConfig.NS);
        
        if (prefix == null) {
            prefix = RampartConfig.NS;
            writer.setPrefix(prefix, RampartConfig.NS);
        }                
        
        writer.writeStartElement(RampartConfig.NS, OPTIMIZE_PARTS_LN);
        
        if((expressions != null) && (expressions.size()>0)){
        	  writer.writeStartElement(RampartConfig.NS, EXPRESSIONS_LN);
        	  Iterator ite = expressions.iterator();
        	  while(ite.hasNext()){
        		  writer.writeStartElement(RampartConfig.NS, EXPRESSION_LN);
        		  String exp = (String)ite.next();
        		  writer.writeCharacters(exp);
        		  writer.writeEndElement();
        	  }
              writer.writeEndElement();
        }
        
        if((namespaces != null) && (namespaces.size()>0)){
        	  writer.writeStartElement(RampartConfig.NS, NAMESPACES_LN);
        	  Iterator ite = namespaces.keySet().iterator();
        	  while(ite.hasNext()){
        		  String strPrefix = (String)ite.next();
        		  String strURI = (String) namespaces.get(strPrefix);
        		  writer.writeStartElement(RampartConfig.NS, NAMESPACE_LN);
        		  writer.writeAttribute(URI_ATTR , strURI);
        		  writer.writeAttribute(PREFIX_ATTR, strPrefix);
        		  writer.writeEndElement();
        	  }
              writer.writeEndElement();
        }
        writer.writeEndElement();
	}
	
	public PolicyComponent normalize() {
		//TODO
		throw new UnsupportedOperationException("TODO");
	}
	
	public boolean isOptional() {
		throw new UnsupportedOperationException("Not relevant");
	}
	
	public boolean equal(PolicyComponent arg0) {
		throw new UnsupportedOperationException("Not relevant");
	}

	


}
