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
package org.apache.rahas;

import org.apache.axis2.context.MessageContext;
import org.apache.rahas.impl.AbstractIssuerConfig;


/**
 * Non-volatile storage interface for for storing security tokens.
 * Persisting should be run as a background process without blocking any other flow.
 * Hence, extending Runnable interface.
 */
public interface TokenPersister extends Runnable {

    /*Key to be used to reference persister object from configuration context.*/
    String TOKEN_PERSISTER_KEY = "org.apache.rahas.TokenPersister";

    /**
     * To check whether any retired tokens are persisted, before performing any operations to
     * manipulate tokens.
     *
     * @return whether any tokens exist in persister.
     */
    boolean isTokensExist();

    /**
     * Check whether a particular token exists in persistence storage given the token id.
     *
     * @param tokenID
     * @return
     */
    boolean isTokenExist(String tokenID);

    /**
     * Persist an array of tokens
     *
     * @param retiredTokens array of security tokens
     * @throws TrustException
     */
    void persistTokens(Token[] retiredTokens) throws TrustException;

    /**
     * Persist a single token
     *
     * @param token
     * @throws TrustException
     */
    void persistToken(Token token) throws TrustException;

    /**
     * Read all the persisted tokens.
     *
     * @return stored tokens as an array of tokens
     */
    Token[] retrieveTokens();

    /**
     * Read a token given it's id.
     *
     * @param tokenId
     * @return
     * @throws TrustException
     */
    Token retrieveToken(String tokenId) throws TrustException;

    /**
     * Obtain the list of token IDs in persistence.
     *
     * @return string array of token ids if exist, else null
     */
    String[] retrieveTokenIDs();

    /**
     * Update the given token in persistence.
     *
     * @param token
     * @throws TrustException
     */
    void updateToken(Token token) throws TrustException;

    /**
     * Remove the token, given the token id.
     *
     * @param tokenId
     * @throws TrustException
     */
    void deleteToken(String tokenId) throws TrustException;

    /**
     * Pass persister configuration to be set in the persister implementation.
     *
     * @param config
     */
    void setConfiguration(AbstractIssuerConfig config) throws TrustException;

    /**
     * Set message context in order to get access to message/config context properties.
     *
     * @param msgContext
     */
    void setMessageContext(MessageContext msgContext);

    /**
     * Notify the persister when persistence needs to happen.
     */
    void notifyPersistence();
}
