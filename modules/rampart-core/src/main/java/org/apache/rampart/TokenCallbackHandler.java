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

import org.apache.rahas.EncryptedKeyToken;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.Token;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustException;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.ws.security.WSParameterCallback;
import org.apache.ws.security.WSPasswordCallback;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

public class TokenCallbackHandler implements CallbackHandler {

    private TokenStorage store;
    private CallbackHandler handler;
    private String tokenIdentifier;
    private RampartConfig config;

    public TokenCallbackHandler(TokenStorage store, CallbackHandler handler) {
        this.store = store;
        this.handler = handler;
        this.tokenIdentifier = null;
    }

    public TokenCallbackHandler(TokenStorage store, CallbackHandler handler, RampartConfig config) {
        this.store = store;
        this.handler = handler;
        this.config = config;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        for (int i = 0; i < callbacks.length; i++) {

            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                String id = pc.getIdentifer();

                if ((pc.getUsage() == WSPasswordCallback.SECURITY_CONTEXT_TOKEN || pc.getUsage() == WSPasswordCallback.CUSTOM_TOKEN)
                        && this.store != null) {
                    Token tok;
                    try {
                        // Pick up the token from the token store
                        tok = this.store.getToken(id);
                        if (tok != null) {
                            // Get the secret and set it in the callback object
                            pc.setKey(tok.getSecret());
                            pc.setCustomToken((Element) tok.getToken());
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        throw new IOException(e.getMessage());
                    }
                } else if (pc.getUsage() == WSPasswordCallback.ENCRYPTED_KEY_TOKEN) {
                    try {

                        String[] tokenIdentifiers = this.store.getTokenIdentifiers();
                        Token tok;

                        for (int j = 0; j < tokenIdentifiers.length; j++) {

                            String tokenNS;
                            tok = this.store.getToken(tokenIdentifiers[j]);

                            if(tok != null && tok.getToken() != null){
                                tokenNS = tok.getToken().getNamespace().getNamespaceURI();
                            } else {
                                continue;
                            }
                            if (tok instanceof EncryptedKeyToken
                                    && ((EncryptedKeyToken) tok).getSHA1().equals(id)) {
                                pc.setKey(tok.getSecret());
                                pc.setCustomToken((Element) tok.getToken());

                                tokenIdentifier = tokenIdentifiers[j];

                            } else if ((tokenNS.equals(RahasConstants.TOK_TYPE_SAML_10_NS) ||
                                        tokenNS.equals(RahasConstants.TOK_TYPE_SAML_20_NS))) {
                                if (tok.getUnattachedReference().getFirstElement().getText().equals(id)) {
                                    pc.setKey(tok.getSecret());
                                    pc.setCustomToken((Element) tok.getToken());
                                }
                            }
                        }

                    } catch (TrustException e) {
                        e.printStackTrace();
                        throw new IOException(e.getMessage());
                    }
                } else {
                    // Handle other types of callbacks with the usual handler
                    if (this.handler != null) {
                        handler.handle(new Callback[] { pc });
                    }
                }

            } else if (callbacks[i] instanceof WSParameterCallback) {
                WSParameterCallback para = (WSParameterCallback) callbacks[i];
                if (para.getProperty() == WSParameterCallback.KDC_DES_AES_FACTOR) {
                    if (config != null) {
                        KerberosConfig krbConfig = config.getKerberosConfig();
                        int factor = 0;
                        String fac = null;
                        if (krbConfig != null
                                && (fac = krbConfig.getProp().getProperty(
                                        KerberosConfig.KDC_DES_AES_FACTOR)) != null) {
                            try {
                                factor = Integer.parseInt(fac);
                            } catch (Exception e) {
                                factor = 0;
                            }
                        }
                        para.setIntValue(factor);
                    }
                } else if (para.getProperty() == WSParameterCallback.SERVICE_PRINCIPLE_PASSWORD) {
                    if (config != null) {
                        KerberosConfig krbConfig = config.getKerberosConfig();
                        String password = null;
                        if (krbConfig != null
                                && (password = krbConfig.getProp().getProperty(
                                        KerberosConfig.SERVICE_PRINCIPLE_PASSWORD)) != null) {
                            para.setStringValue(password);
                        }
                    }
                }
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }

    public void removeEncryptedToken() throws RampartException {

        try {
            if (tokenIdentifier != null) {

                this.store.removeToken(tokenIdentifier);
            }
        } catch (TrustException e) {
            throw new RampartException(e.getMessage(), e);
        }
    }

}
