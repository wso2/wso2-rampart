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

package org.apache.rahas.impl;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axis2.description.Parameter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.TrustException;
import org.apache.rahas.impl.util.SAMLCallbackHandler;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;

import javax.xml.namespace.QName;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

/**
 * Configuration manager for the <code>SAMLTokenIssuer</code>
 *
 * @see SAMLTokenIssuer
 */
public class SAMLTokenIssuerConfig extends AbstractIssuerConfig {
    
	Log log = LogFactory.getLog(SAMLTokenIssuerConfig.class);
	
    /**
     * The QName of the configuration element of the SAMLTokenIssuer
     */
    public final static QName SAML_ISSUER_CONFIG = new QName("saml-issuer-config");

    /**
     * Element name to include the alias of the private key to sign the response or
     * the issued token
     */
    private final static QName ISSUER_KEY_ALIAS = new QName("issuerKeyAlias");

    /**
	 * Element name to include the password of the private key to sign the response or the issued
	 * token
	 */
	private final static QName ISSUER_KEY_PASSWD = new QName("issuerKeyPassword");

	/**
	 * Element name of the attribute call-back handler
	 */
	private final static QName ATTR_CALLBACK_HANDLER_NAME = new QName("attrCallbackHandlerName");

    /**
     * Element to specify the lifetime of the SAMLToken
     * Dafaults to 300000 milliseconds (5 mins)
     */
    private final static QName TTL = new QName("timeToLive");

    /**
     * Element to list the trusted services
     */
    private final static QName TRUSTED_SERVICES = new QName("trusted-services");

    private final static QName KEY_SIZE = new QName("keySize");

    private final static QName SERVICE = new QName("service");
    private final static QName ALIAS = new QName("alias");

    public final static QName USE_SAML_ATTRIBUTE_STATEMENT = new QName("useSAMLAttributeStatement");

    public final static QName ISSUER_NAME = new QName("issuerName");
    
    public final static QName SAML_CALLBACK_CLASS = new QName("dataCallbackHandlerClass");
        
    protected String issuerKeyAlias;
    protected String issuerKeyPassword;
    protected String issuerName;
    protected Map trustedServices = new HashMap();
    protected String trustStorePropFile;
    protected SAMLCallbackHandler callbackHandler;
    protected String callbackHandlerName;
    protected OMElement persisterElement = null;
    protected String persisterClassName = null;
    protected Map<String, String> persisterPropertyMap = null;
    protected boolean tokenStoreDisabled = false;
  
    /**
     * Create a new configuration with issuer name and crypto information
     * @param issuerName Name of the issuer
     * @param cryptoProviderClassName WSS4J Crypto impl class name
     * @param cryptoProps Configuration properties of crypto impl
     */
    public SAMLTokenIssuerConfig(String issuerName, String cryptoProviderClassName, Properties cryptoProps) {
        this.issuerName = issuerName;
        this.setCryptoProperties(cryptoProviderClassName, cryptoProps);
    }
    
    /**
     * Create a SAMLTokenIssuer configuration with a config file picked from the
     * given location.
     * @param configFilePath Path to the config file
     * @throws TrustException
     */
    public SAMLTokenIssuerConfig(String configFilePath) throws TrustException {
        FileInputStream fis;
        StAXOMBuilder builder;
        try {
            fis = new FileInputStream(configFilePath);
            builder = new StAXOMBuilder(fis);
        } catch (Exception e) {
            throw new TrustException("errorLoadingConfigFile",
                    new String[] { configFilePath });
        }
        this.load(builder.getDocumentElement());
    }
    
    /**
     * Create a  SAMLTokenIssuer configuration using the give config element
     * @param elem Configuration element as an <code>OMElement</code>
     * @throws TrustException
     */
    public SAMLTokenIssuerConfig(OMElement elem) throws TrustException {
        this.load(elem);
    }

    private void load(OMElement elem) throws TrustException {
        OMElement proofKeyElem = elem.getFirstChildWithName(PROOF_KEY_TYPE);
        if (proofKeyElem != null) {
            this.proofKeyType = proofKeyElem.getText().trim();
        }

        OMElement callbackNameElem = elem.getFirstChildWithName(ATTR_CALLBACK_HANDLER_NAME);
        if (callbackNameElem != null) {
            this.callbackHandlerName = callbackNameElem.getText().trim();
        }
        
        //The alias of the private key
        OMElement userElem = elem.getFirstChildWithName(ISSUER_KEY_ALIAS);
        if (userElem != null) {
            this.issuerKeyAlias = userElem.getText().trim();
        }

        if (this.issuerKeyAlias == null || "".equals(this.issuerKeyAlias)) {
            throw new TrustException("samlIssuerKeyAliasMissing");
        }

        OMElement issuerKeyPasswdElem = elem.getFirstChildWithName(ISSUER_KEY_PASSWD);
        if (issuerKeyPasswdElem != null) {
            this.issuerKeyPassword = issuerKeyPasswdElem.getText().trim();
        }

        if (this.issuerKeyPassword == null || "".equals(this.issuerKeyPassword)) {
            throw new TrustException("samlIssuerKeyPasswdMissing");
        }

        OMElement issuerNameElem = elem.getFirstChildWithName(ISSUER_NAME);
        if (issuerNameElem != null) {
            this.issuerName = issuerNameElem.getText().trim();
        }

        if (this.issuerName == null || "".equals(this.issuerName)) {
            throw new TrustException("samlIssuerNameMissing");
        }

        this.cryptoPropertiesElement = elem.getFirstChildWithName(CRYPTO_PROPERTIES);
        if (this.cryptoPropertiesElement != null) {
            if ((this.cryptoElement =
                this.cryptoPropertiesElement .getFirstChildWithName(CRYPTO)) == null){
                // no children. Hence, prop file should have been defined
                this.cryptoPropertiesFile = this.cryptoPropertiesElement .getText().trim();
            }
            // else Props should be defined as children of a crypto element
        }

        OMElement keyCompElem = elem.getFirstChildWithName(KeyComputation.KEY_COMPUTATION);
        if (keyCompElem != null && keyCompElem.getText() != null && !"".equals(keyCompElem.getText())) {
            this.keyComputation = Integer.parseInt(keyCompElem.getText());
        }

        //time to live
        OMElement ttlElem = elem.getFirstChildWithName(TTL);
        if (ttlElem != null) {
            try {
                this.ttl = Long.parseLong(ttlElem.getText().trim());
            } catch (NumberFormatException e) {
                throw new TrustException("invlidTTL");
            }
        }

        OMElement keySizeElem = elem.getFirstChildWithName(KEY_SIZE);
        if (keySizeElem != null) {
            try {
                this.keySize = Integer.parseInt(keySizeElem.getText().trim());
            } catch (NumberFormatException e) {
                throw new TrustException("invalidKeysize");
            }
        }

        this.addRequestedAttachedRef = elem
                .getFirstChildWithName(ADD_REQUESTED_ATTACHED_REF) != null;
        this.addRequestedUnattachedRef = elem
                .getFirstChildWithName(ADD_REQUESTED_UNATTACHED_REF) != null;

        //Process trusted services
        OMElement trustedServices = elem.getFirstChildWithName(TRUSTED_SERVICES);

        /*
        * If there are trusted services add them to a list
        * Only trusts myself to issue tokens to :
        * In this case the STS is embedded in the service as well and
        * the issued token can only be used with that particular service
        * since the response secret is encrypted by the service's public key
        */
        if (trustedServices != null) {
            //Now process the trusted services
            Iterator servicesIter = trustedServices.getChildrenWithName(SERVICE);
            while (servicesIter.hasNext()) {
                OMElement service = (OMElement) servicesIter.next();
                OMAttribute aliasAttr = service.getAttribute(ALIAS);
                if (aliasAttr == null) {
                    //The certificate alias is a must
                    throw new TrustException("aliasMissingForService",
                                             new String[]{service.getText().trim()});
                }
                if (this.trustedServices == null) {
                    this.trustedServices = new HashMap();
                }

                //Add the trusted service and the alias to the map of services
                this.trustedServices.put(service.getText().trim(), aliasAttr.getAttributeValue());
            }

            //There maybe no trusted services as well, Therefore do not 
            //throw an exception when there are no trusted in the list at the 
            //moment
        }
        
        
       	OMElement attrElemet = elem.getFirstChildWithName(SAML_CALLBACK_CLASS);
		if (attrElemet != null) {
				try {
					String value = attrElemet.getText();
					Class handlerClass = Class.forName(value);
					this.callbackHandler = (SAMLCallbackHandler)handlerClass.newInstance();
				} catch (ClassNotFoundException e) {
					log.error("Error loading class" , e);
					throw new TrustException("Error loading class" , e);
				} catch (InstantiationException e) {
					log.error("Error instantiating class" , e);
					throw new TrustException("Error instantiating class" , e);
				} catch (IllegalAccessException e) {
					log.error("Illegal Access" , e);
					throw new TrustException("Illegal Access" , e);
				}
		}
        
        //read & set if token storage is disabled
        OMElement storageDisabledElement = elem.getFirstChildWithName(TOKEN_STORE_DISABLED_QN);
        if (storageDisabledElement != null) {
            tokenStoreDisabled = Boolean.parseBoolean(storageDisabledElement.getText());
        }

        //read token persister configuration
        persisterElement = elem.getFirstChildWithName(TOKEN_PERSISTER_QN);
        //read persister configuration only if they are set
        if (persisterElement != null) {
            persisterClassName = persisterElement.getAttributeValue(ATTR_CLASS_QN);
            persisterPropertyMap = readPropertyMap(persisterElement);
        }

    }

    /**
     * Util method to extract property names and values to a property map
     * @param propertySetElement
     * @return property map
     */
    private Map<String, String> readPropertyMap(OMElement propertySetElement) {
        Map<String, String> propMap = new HashMap<String, String>();
        Iterator<?> ite = propertySetElement.getChildrenWithName(LOCAL_PROPERTY_QN);
        while (ite.hasNext()) {
            OMElement propertyElement = (OMElement) ite.next();
            String propertyName = propertyElement.getAttributeValue(ATTR_PROP_NAME_QN);
            String propertyValue = propertyElement.getText();
            propMap.put(propertyName, propertyValue);
        }
        return propMap;
    }

    /**
     * Generate an Axis2 parameter for this configuration
     * @return An Axis2 Parameter instance with configuration information
     */
    public Parameter getParameter() {
        Parameter param = new Parameter();
        
        OMFactory fac = OMAbstractFactory.getOMFactory();
        
        OMElement paramElem = fac.createOMElement("Parameter", null);
        paramElem.addAttribute("name", SAML_ISSUER_CONFIG.getLocalPart(), null);
        
        OMElement configElem = fac.createOMElement(SAML_ISSUER_CONFIG, paramElem);
        
        OMElement issuerNameElem = fac.createOMElement(ISSUER_NAME, configElem);
        issuerNameElem.setText(this.issuerName);
        
        OMElement issuerKeyAliasElem = fac.createOMElement(ISSUER_KEY_ALIAS, configElem);
        issuerKeyAliasElem.setText(this.issuerKeyAlias);
        
        OMElement issuerKeyPasswd = fac.createOMElement(ISSUER_KEY_PASSWD, configElem);
        issuerKeyPasswd.setText(this.issuerKeyPassword);
        
        OMElement callbackHandlerName = fac.createOMElement(ATTR_CALLBACK_HANDLER_NAME, configElem);
        callbackHandlerName.setText(this.callbackHandlerName);
        
        OMElement timeToLive = fac.createOMElement(TTL, configElem);
        timeToLive.setText(String.valueOf(this.ttl));

        configElem.addChild(this.cryptoPropertiesElement);
        
        OMElement keySizeElem = fac.createOMElement(KEY_SIZE, configElem);
        keySizeElem.setText(Integer.toString(this.keySize));
        
        if(this.addRequestedAttachedRef) {
            fac.createOMElement(ADD_REQUESTED_ATTACHED_REF, configElem);
        }
        if(this.addRequestedUnattachedRef) {
            fac.createOMElement(ADD_REQUESTED_UNATTACHED_REF, configElem);
        }
        
        OMElement keyCompElem = fac.createOMElement(KeyComputation.KEY_COMPUTATION, configElem);
        keyCompElem.setText(Integer.toString(this.keyComputation));
        
        OMElement proofKeyTypeElem = fac.createOMElement(PROOF_KEY_TYPE, configElem);
        proofKeyTypeElem.setText(this.proofKeyType);
        
        OMElement trustedServicesElem = fac.createOMElement(TRUSTED_SERVICES, configElem);
        for (Iterator iterator = this.trustedServices.keySet().iterator(); iterator.hasNext();) {
            String service = (String) iterator.next();
            OMElement serviceElem = fac.createOMElement(SERVICE, trustedServicesElem);
            serviceElem.setText(service);
            serviceElem.addAttribute("alias", (String)this.trustedServices.get(service), null);
            
        }

        //set storage disable parameter
        OMElement storageDisabledElement = fac.createOMElement(TOKEN_STORE_DISABLED_QN, configElem);
        storageDisabledElement.setText(Boolean.toString(tokenStoreDisabled));

        //set the persister element if configured
        if (persisterClassName != null) {
            OMElement persisterElement = fac.createOMElement(TOKEN_PERSISTER_QN, configElem);
            persisterElement.addAttribute(LOCAL_PROPERTY_CLASS, this.getPersisterClassName(), null);
            if (this.persisterPropertyMap != null && this.persisterPropertyMap.size() != 0) {
                for (Map.Entry<String, String> entry : persisterPropertyMap.entrySet()) {
                    OMElement propElement = fac.createOMElement(LOCAL_PROPERTY_QN, persisterElement);
                    propElement.addAttribute(ATTR_PROP_NAME, entry.getKey(), null);
                    propElement.setText(entry.getValue());
                }
            }
        }

        param.setName(SAML_ISSUER_CONFIG.getLocalPart());
        param.setParameterElement(paramElem);
        param.setValue(paramElem);
        param.setParameterType(Parameter.OM_PARAMETER);
        
        return param;
    }
    
    public void setIssuerKeyAlias(String issuerKeyAlias) {
        this.issuerKeyAlias = issuerKeyAlias;
    }

    public String getIssuerKeyAlias() {
        return issuerKeyAlias;
    }

    public void setIssuerKeyPassword(String issuerKeyPassword) {
        this.issuerKeyPassword = issuerKeyPassword;
    }

    public String getIssuerKeyPassword() {
        return issuerKeyPassword;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public void setTrustedServices(Map trustedServices) {
        this.trustedServices = trustedServices;
    }

    public void setTrustStorePropFile(String trustStorePropFile) {
        this.trustStorePropFile = trustStorePropFile;
    }

    /**
     * Add a new trusted service endpoint address with its certificate
     * @param address Service endpoint address
     * @param alias certificate alias
     */
    public void addTrustedServiceEndpointAddress(String address, String alias) {
        this.trustedServices.put(address, alias);
    }
    
    /**
     * Set crypto information using WSS4J mechanisms
     * 
     * @param providerClassName
     *            Provider class - an implementation of
     *            org.apache.ws.security.components.crypto.Crypto
     * @param props Configuration properties
     */
    public void setCryptoProperties(String providerClassName, Properties props) {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        this.cryptoPropertiesElement= fac.createOMElement(CRYPTO_PROPERTIES);
        OMElement cryptoElem = fac.createOMElement(CRYPTO, this.cryptoPropertiesElement);
        cryptoElem.addAttribute(PROVIDER.getLocalPart(), providerClassName, null);
        Enumeration keys =  props.keys();
        while (keys.hasMoreElements()) {
            String prop = (String) keys.nextElement();
            String value = (String)props.get(prop);
            OMElement propElem = fac.createOMElement(PROPERTY, cryptoElem);
            propElem.setText(value);
            propElem.addAttribute("name", prop, null);
        }
    }

    /**
     * Return the list of trusted services as a <code>java.util.Map</code>.
     * The services addresses are the keys and cert aliases available under 
     * those keys. 
     * @return
     */
    public Map getTrustedServices() {
        return trustedServices;
    }

    @Deprecated
	public SAMLCallbackHandler getCallbackHander() {
		return callbackHandler;
	}

    @Deprecated
	public void setCallbackHander(SAMLCallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
	}
	
	public SAMLCallbackHandler getCallbackHandler() {
		return callbackHandler;
	}

	public void setCallbackHandler(SAMLCallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
	}
	
	public String getCallbackHandlerName() {
		return callbackHandlerName;
	}

	public void setCallbackHandlerName(String callbackHandlerName) {
		this.callbackHandlerName = callbackHandlerName;
	}

    /**
     * Uses the <code>wst:AppliesTo</code> to figure out the certificate to
     * encrypt the secret in the SAML token
     *
     * @param crypto
     * @param serviceAddress
     *            The address of the service
     * @return
     * @throws org.apache.ws.security.WSSecurityException
     */
    public X509Certificate getServiceCert(Crypto crypto, String serviceAddress) throws WSSecurityException {

        if (serviceAddress != null && !"".equals(serviceAddress)) {
            String alias = (String) this.trustedServices.get(serviceAddress);
            if (alias != null) {
                return crypto.getCertificates(alias)[0];
            } else {
                alias = (String) this.trustedServices.get("*");
                return crypto.getCertificates(alias)[0];
            }
        } else {
            String alias = (String) this.trustedServices.get("*");
            return crypto.getCertificates(alias)[0];
        }

    }

    public String getPersisterClassName() {
        return persisterClassName;
    }

    public void setPersisterClassName(String persisterClassName) {
        this.persisterClassName = persisterClassName;
    }

    public Map getPersisterPropertyMap() {
        return persisterPropertyMap;
    }

    public void setPersisterPropertyMap(Map persisterPropertyMap) {
        this.persisterPropertyMap = persisterPropertyMap;
    }

    public OMElement getPersisterElement() {
        return persisterElement;
    }

    public boolean isTokenStoreDisabled() {
        return tokenStoreDisabled;
    }

    public void setTokenStoreDisabled(boolean tokenStoreDisabled) {
        this.tokenStoreDisabled = tokenStoreDisabled;
    }
    
}
