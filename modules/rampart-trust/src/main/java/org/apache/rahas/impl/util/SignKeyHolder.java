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

package org.apache.rahas.impl.util;


import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

/**
 * This class is used to store the signing credentials.
 */
public class SignKeyHolder implements X509Credential {

    private String signatureAlgorithm = null;

    private X509Certificate[] issuerCerts = null;

	private PrivateKey issuerPK = null;


    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

 
    public X509Certificate[] getIssuerCerts() {
        return issuerCerts;
    }

    public void setIssuerCerts(X509Certificate[] issuerCerts) {
        this.issuerCerts = issuerCerts;
    }

    public PrivateKey getIssuerPK() {
        return issuerPK;
    }

    public void setIssuerPK(PrivateKey issuerPK) {
        this.issuerPK = issuerPK;
    }

    public SignKeyHolder(){
    }


    public X509Certificate getEntityCertificate() {
        return issuerCerts[0];
    }


    public Collection<X509Certificate> getEntityCertificateChain() {
        return Arrays.asList(issuerCerts);
    }

    public Collection<X509CRL> getCRLs() {
        return null;
    }

    public String getEntityId() {
        return null;
    }

    public UsageType getUsageType() {
        return null;
    }

    public Collection<String> getKeyNames() {
        return null;
    }

    public PublicKey getPublicKey() {
        return null;
    }

    public PrivateKey getPrivateKey() {
        return issuerPK;
    }

    public SecretKey getSecretKey() {
        return null;
    }

    public CredentialContextSet getCredentalContextSet() {
        return null;
    }

    public Class<? extends Credential> getCredentialType() {
        return null;
    }
}
