/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

package org.apache.rampart;

import org.apache.axiom.soap.SOAP11Constants;
import org.apache.ws.security.WSConstants;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;

public class ValidatorData {

    private RampartMessageData rmd;
    ArrayList encryptedDataRefIds = new ArrayList();
    private String bodyEncrDataId;
    
    public ValidatorData(RampartMessageData rmd) {
        this.rmd = rmd;
        //this.extractEncryptedPartInformation();
    }
    
    private void extractEncryptedPartInformation() {
        Element start = rmd.getDocument().getDocumentElement();
        if(start != null) {
            extractEncryptedPartInformation(start);
        }
        
    }
    
    private void extractEncryptedPartInformation(Element parent) {

        NodeList childNodes = parent.getChildNodes();
        Node node;
        for (int i = 0; i < childNodes.getLength(); i++) {
            node = childNodes.item(i);
            if (node instanceof Element) {
                Element elem = (Element) node;
                if (elem.getNamespaceURI() != null 
                        && elem.getNamespaceURI().equals(WSConstants.ENC_NS)
                        && elem.getLocalName().equals(
                                EncryptionConstants._TAG_ENCRYPTEDDATA)) {
                    if (parent.getLocalName().equals(
                                    SOAP11Constants.BODY_LOCAL_NAME)
                            && parent.getNamespaceURI().equals(
                                    rmd.getSoapConstants().getEnvelopeURI())) {
                        this.bodyEncrDataId = elem.getAttribute("Id");
                    } else {
                        encryptedDataRefIds.add(elem.getAttribute("Id"));
                    }
                    break;
                } else {
                    extractEncryptedPartInformation(elem);
                }
            }
        }
    }

    public ArrayList getEncryptedDataRefIds() {
        return encryptedDataRefIds;
    }

    public RampartMessageData getRampartMessageData() {
        return rmd;
    }

    public String getBodyEncrDataId() {
        return bodyEncrDataId;
    }
    
}
