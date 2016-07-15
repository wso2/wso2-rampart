/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.rahas.impl.util;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;

/**
 * Document builder factory that conforms to JAXP.
 */
class DOOMDocumentBuilderFactory extends DocumentBuilderFactory {
    private Schema schema;

    public DocumentBuilder newDocumentBuilder()
            throws ParserConfigurationException {
        return new DOOMDocumentBuilder(schema);
    }

    public Object getAttribute(String arg0) throws IllegalArgumentException {
        // TODO
        throw new UnsupportedOperationException("TODO");
    }

    public void setAttribute(String arg0, Object arg1)
            throws IllegalArgumentException {
        // // TODO
        // throw new UnsupportedOperationException("TODO");
    }

    public void setFeature(String name, boolean value)
            throws ParserConfigurationException {
        // TODO TODO OS
    }

    public boolean getFeature(String arg0) throws ParserConfigurationException {
        // TODO TODO
        throw new UnsupportedOperationException("TODO");
    }


    public Schema getSchema() {
        return this.schema;
    }

    public void setSchema(Schema schema) {
        this.schema = schema;
    }

}
