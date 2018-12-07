package org.apache.rahas.impl.util;

import org.apache.rahas.RahasConstants;
import org.apache.rahas.impl.SAMLTokenIssuerConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.WSSecurityException;
import org.apache.xml.security.signature.XMLSignature;

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

    /**
     * Get the signature algorithm
     * @param config SAML Token Issuer Configuration
     * @param issuerCerts Issuer Certificates
     * @return Signature algorithm URL
     */
    public static String getSignatureAlgorithm(SAMLTokenIssuerConfig config, X509Certificate[] issuerCerts) {
        String sigAlgo = config.getSignatureAlgorithm();
        if (sigAlgo == null || sigAlgo.isEmpty()) {
            sigAlgo =  XMLSignature.ALGO_ID_SIGNATURE_RSA;
        }
        String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
        if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
            sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
        }
        return sigAlgo;
    }

    /**
     * Get the digest algorithm
     * @param config SAML Token Issuer Configuration
     * @return Digest algorithm URL
     */
    public static String getDigestAlgorithm(SAMLTokenIssuerConfig config) {
        String digestAlgorithm = config.getDigestAlgorithm();
        if (digestAlgorithm == null || digestAlgorithm.isEmpty()) {
            digestAlgorithm =  RahasConstants.DEFAULT_DIGEST_ALGORITHM;
        }
        return digestAlgorithm;
    }
}

