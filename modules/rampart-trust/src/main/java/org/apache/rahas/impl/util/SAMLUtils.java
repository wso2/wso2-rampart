package org.apache.rahas.impl.util;

import org.apache.rahas.impl.SAMLTokenIssuerConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.WSSecurityException;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.ArrayList;

public class SAMLUtils {


    public static Collection<X509Certificate> getCertChainCollection(X509Certificate[] issuerCerts){

         ArrayList<X509Certificate> certCollection = new ArrayList<X509Certificate>();

        if (issuerCerts == null) {
            return certCollection;
        } else {
            for (X509Certificate cert : issuerCerts) {
                certCollection.add(cert);    
            }
        }

        return certCollection;

    }
}

