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

import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;

import javax.xml.parsers.DocumentBuilderFactory;
import java.lang.reflect.Field;

/**
 * Custom OpenSAML 1.x {@link ParserPool} implementation that uses a DOM aware Axiom implementation
 * instead of requesting a {@link DocumentBuilderFactory} using JAXP.
 */
public class AxiomParserPool extends StaticBasicParserPool {
    public AxiomParserPool() {
        DocumentBuilderFactory dbf = new DOOMDocumentBuilderFactory();

        // Unfortunately, ParserPool doesn't allow to set the DocumentBuilderFactory, so that we
        // have to use reflection here.
        try {
            Field dbfField = StaticBasicParserPool.class.getDeclaredField("builderFactory");
            dbfField.setAccessible(true);
            dbfField.set(this, dbf);
        } catch (IllegalAccessException ex) {
            throw new IllegalAccessError(ex.getMessage());
        } catch (NoSuchFieldException ex) {
            throw new NoSuchFieldError(ex.getMessage());
        }
    }
}