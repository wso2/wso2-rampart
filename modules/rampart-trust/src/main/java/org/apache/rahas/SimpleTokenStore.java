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

import org.apache.axiom.om.OMElement;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.impl.AbstractIssuerConfig;
import org.apache.rahas.impl.SAMLTokenIssuerConfig;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.message.token.Reference;

import javax.xml.namespace.QName;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * In-memory implementation of the token storage
 */
public class SimpleTokenStore implements TokenStorage, Serializable {

    private static Log log = LogFactory.getLog(SimpleTokenStore.class);

    protected Map tokens = new Hashtable();

    protected transient volatile Boolean tokenStoreDisabled = null;

    /*If a persister is configured to handle non-volatile storage of tokens, take a reference to it*/
    protected transient TokenPersister tokenPersister = null;

    protected transient Integer maxInMemoryTokens = null;

    private static final int DEFAULT_IN_MEMORY_THRESHOLD = 500;

    //maintains a list of ids of the tokens in persistence.
    protected List<String> persistedTokenIDList = new ArrayList<String>();

    /**
     * We use a read write lock to improve concurrency while avoiding concurrent modification
     * exceptions.  We allow concurrent reads and avoid concurrent reads and modifications
     * ReentrantReadWriteLock supports a maximum of 65535 recursive write locks and 65535 read locks
     */
    protected final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();

    protected final Lock readLock = readWriteLock.readLock();

    protected final Lock writeLock = readWriteLock.writeLock();

    public void add(Token token) throws TrustException {
        //check whether a token persister is configured.
        if (tokenPersister == null) {
            getTokenPersister();
        }
        //if a token persister is not configured, continue with in-memory one.
        if (tokenPersister == null) {
            if (token != null && !"".equals(token.getId()) && token.getId() != null) {

                writeLock.lock();

                try {
                    if (this.tokens.keySet().size() == 0
                        || ((this.tokens.keySet().size() > 0) && !this.tokens.keySet().contains(
                            token.getId()))) {

                        tokens.put(token.getId(), token);

                    } else {
                        throw new TrustException("tokenAlreadyExists", new String[]{token.getId()});
                    }
                } finally {
                    writeLock.unlock();
                }
            }
        } else {//if a token persister is configured, handle persistence
            getThreshold();

            if (token != null && !"".equals(token.getId()) && token.getId() != null) {
                /* if this is the first time that the store is used, try to load
                persisted tokens list from file system */
                if ((this.tokens.keySet().size() == 0) && (this.persistedTokenIDList.size() == 0)) {
                    populatePersistedTokenIDs();
                }
                writeLock.lock();

                try {
                    if (this.tokens.keySet().size() == 0
                        || ((this.tokens.keySet().size() > 0) && (tokens.keySet().size() < maxInMemoryTokens)
                            && !isTokenExist(token.getId()))) {

                        tokens.put(token.getId(), token);

                    } else if (((tokens.keySet().size() == maxInMemoryTokens) ||
                                (tokens.keySet().size() > maxInMemoryTokens)) &&
                               (!isTokenExist(token.getId()))) {
                        //notify persister
                        tokenPersister.notifyPersistence();

                        //add token to the store
                        tokens.put(token.getId(), token);

                    } else {
                        throw new TrustException("tokenAlreadyExists", new String[]{token.getId()});
                    }
                } finally {
                    writeLock.unlock();
                }
            }
        }
    }

    public void update(Token token) throws TrustException {
        if (tokenPersister == null) {
            getTokenPersister();
        }
        if (tokenPersister == null) {

            if (token != null && token.getId() != null && token.getId().trim().length() != 0) {

                writeLock.lock();

                try {
                    if (!this.tokens.keySet().contains(token.getId())) {
                        throw new TrustException("noTokenToUpdate", new String[]{token.getId()});
                    }
                    this.tokens.put(token.getId(), token);
                } finally {
                    writeLock.unlock();
                }
            }
        } else {
            /* if this is the first time that the store is used, try to load
                persisted tokens list from file system */
            if ((this.tokens.keySet().size() == 0) && (this.persistedTokenIDList.size() == 0)) {
                populatePersistedTokenIDs();
            }
            if (token != null && token.getId() != null && token.getId().trim().length() != 0) {
                writeLock.lock();
                try {
                    if (this.tokens.containsKey(token.getId())) {
                        this.tokens.put(token.getId(), token);
                    } else if (this.persistedTokenIDList.contains(token.getId())) {
                        if (tokenPersister.isTokenExist(token.getId())) {
                            tokenPersister.updateToken(token);
                        }
                    } else {
                        throw new TrustException("noTokenToUpdate", new String[]{token.getId()});
                    }
                } finally {
                    writeLock.unlock();
                }
            }
        }
    }

    public String[] getTokenIdentifiers() throws TrustException {
        List identifiers = new ArrayList();
        if (tokenPersister == null) {
            getTokenPersister();
        }
        if (tokenPersister == null) {

            readLock.lock();
            try {
                for (Iterator iterator = tokens.keySet().iterator(); iterator.hasNext();) {
                    identifiers.add(iterator.next());
                }
            } finally {
                readLock.unlock();
            }
            return (String[]) identifiers.toArray(new String[identifiers.size()]);
        } else {
            /* if this is the first time that the store is used, try to load
                persisted tokens list from file system */
            if ((this.tokens.keySet().size() == 0) && (this.persistedTokenIDList.size() == 0)) {
                populatePersistedTokenIDs();
            }
            readLock.lock();
            try {
                for (Iterator iterator = tokens.keySet().iterator(); iterator.hasNext();) {
                    identifiers.add(iterator.next());
                }
                if (persistedTokenIDList.size() != 0) {
                    for (Object persistedTokenID : persistedTokenIDList) {
                        identifiers.add(persistedTokenID);
                    }
                    return (String[]) identifiers.toArray(new String[identifiers.size()]);
                }
            } finally {
                readLock.unlock();
            }
        }
        return (String[]) identifiers.toArray(new String[identifiers.size()]);
    }

    public Token[] getValidTokens() throws TrustException {
        return getTokens(new int[]{Token.ISSUED, Token.RENEWED});
    }

    public Token[] getRenewedTokens() throws TrustException {
        return getTokens(Token.RENEWED);
    }


    public Token[] getCancelledTokens() throws TrustException {
        return getTokens(Token.CANCELLED);
    }

    public Token[] getExpiredTokens() throws TrustException {
        return getTokens(Token.EXPIRED);
    }
    //TODO:handle persistence if enabled.
    private Token[] getTokens(int[] states) throws TrustException {
        processTokenExpiry();
        List tokens = new ArrayList();

        readLock.lock();

        try {
            for (Iterator iterator = this.tokens.values().iterator(); iterator.hasNext();) {
                Token token = (Token) iterator.next();
                for (int i = 0; i < states.length; i++) {
                    if (token.getState() == states[i]) {
                        tokens.add(token);
                        break;
                    }
                }
            }
        } finally {
            readLock.unlock();
        }
        return (Token[]) tokens.toArray(new Token[tokens.size()]);
    }
    //TODO:handle persistence if enabled.
    private Token[] getTokens(int state) throws TrustException {
        processTokenExpiry();
        List tokens = new ArrayList();

        readLock.lock();

        try {
            for (Iterator iterator = this.tokens.values().iterator(); iterator.hasNext();) {
                Token token = (Token) iterator.next();
                if (token.getState() == state) {
                    tokens.add(token);
                }
            }
        } finally {
            readLock.unlock();
        }
        return (Token[]) tokens.toArray(new Token[tokens.size()]);
    }

    public Token getToken(String id) throws TrustException {
        if (tokenPersister == null) {
            getTokenPersister();
        }
        Token token = null;
        if (tokenPersister == null) {
            token = getTokenFromMemory(id);
        } else {
            /* if this is the first time that the store is used, try to load
                persisted tokens list from file system */
            if ((this.tokens.keySet().size() == 0) && (this.persistedTokenIDList.size() == 0)) {
                populatePersistedTokenIDs();
            }
            token = getTokenFromMemory(id);
            if (token == null) {
                readLock.lock();
                try {
                    //get from the persistence storage
                    if (persistedTokenIDList.contains(id)) {
                        if (tokenPersister.isTokenExist(id)) {
                            token = tokenPersister.retrieveToken(id);
                            //process if the token is expired
                            setIfTokenExpired(token);
                        }
                    } else {
                        for (String tokenID : persistedTokenIDList) {
                            Token tempToken = tokenPersister.retrieveToken(tokenID);
                            OMElement elem = tempToken.getAttachedReference();
                            if (elem != null && tokenID.equals(this.getIdFromSTR(elem))) {
                                token = tempToken;
                                break; //exit loop if token found, assuming tokenID is unique.
                            }
                            elem = tempToken.getUnattachedReference();
                            if (elem != null && tokenID.equals(this.getIdFromSTR(elem))) {
                                token = tempToken;
                                break; //exit loop if token found, assuming tokenID is unique.
                            }
                        }
                    }
                } finally {
                    readLock.unlock();
                }
            }
        }
        return token;
    }

    private Token getTokenFromMemory(String tokenID) throws TrustException {
        processTokenExpiry();

        readLock.lock();
        Token token;
        try {

            token = (Token) this.tokens.get(tokenID);

            if (token == null) {
                //Try to find the token using attached refs & unattached refs
                for (Iterator iterator = this.tokens.values().iterator(); iterator.hasNext();) {
                    Token tempToken = (Token) iterator.next();
                    OMElement elem = tempToken.getAttachedReference();
                    if (elem != null && tokenID.equals(this.getIdFromSTR(elem))) {
                        token = tempToken;
                        break; //exit loop if token found, assuming tokenID is unique.//TODO:double check
                    }
                    elem = tempToken.getUnattachedReference();
                    if (elem != null && tokenID.equals(this.getIdFromSTR(elem))) {
                        token = tempToken;
                        break; //exit loop if token found, assuming tokenID is unique.
                    }
                }
            }

        } finally {
            readLock.unlock();
        }
        return token;
    }

    public void removeToken(String id) throws TrustException {
        if (tokenPersister == null) {
            getTokenPersister();
        }
        if (tokenPersister == null) {
            writeLock.lock();
            try {
                this.tokens.remove(id);
            } finally {
                writeLock.unlock();
            }
        } else {
            /* if this is the first time that the store is used, try to load
                persisted tokens list from file system */
            if ((this.tokens.keySet().size() == 0) && (this.persistedTokenIDList.size() == 0)) {
                populatePersistedTokenIDs();
            }
            writeLock.lock();
            try {
                if (tokens.containsKey(id)) {
                    this.tokens.remove(id);
                } else if (persistedTokenIDList.contains(id)) {
                    if (tokenPersister.isTokenExist(id)) {
                        tokenPersister.deleteToken(id);
                        persistedTokenIDList.remove(id);
                    }
                } else {
                    String errorMsg = "Token to be removed doesn't exist.";
                    log.error(errorMsg);
                    throw new TrustException(errorMsg);
                }
            } finally {
                writeLock.unlock();
            }
        }
    }

    /**
     * Get the tokens in memory to a list and return. Not called by multiple threads, hence no 
     * double checked locking.
     * @return
     * @throws TrustException
     */
    public List<Token> getStorageTokens() throws TrustException {
        List<Token> storageTokenList = new ArrayList<Token>();
        readLock.lock();

        try {
            for (Iterator iterator = tokens.values().iterator(); iterator.hasNext();) {
                Token token = (Token) iterator.next();
                storageTokenList.add(token);
            }
        } finally {
            readLock.unlock();
        }
        return storageTokenList;
    }

    public void handlePersistence(List<?> persistingTokens) throws TrustException {
        if (tokenPersister == null) {
            getTokenPersister();
        }
        for (Object persistingToken : persistingTokens) {
            String persistingTokenID = null;
            writeLock.lock();
            try {
                persistingTokenID = (String) persistingToken;
                //persist the token using persistence mechanism provided by persister
                if (((Token) tokens.get(persistingTokenID)).isPersistenceEnabled()) {
                    tokenPersister.persistToken((Token) tokens.get(persistingTokenID));
                }
                //remove the token from in memory map
                tokens.remove(persistingTokenID);
                //add token ID to persisted tokens list
                persistedTokenIDList.add(persistingTokenID);
            } catch (TrustException e) {
                String errorMsg = "Error in persisting token: " + persistingTokenID;
                log.error(errorMsg, e);
                throw new TrustException(errorMsg, e);
            } finally {
                writeLock.unlock();
            }
        }
    }

    public void handlePersistenceOnShutdown() throws TrustException {
        if (tokenPersister == null) {
            getTokenPersister();
        }
        if (tokenPersister != null) {
            readLock.lock();
            try {
                for (Object token : tokens.values()) {
                    if (((Token) token).isPersistenceEnabled()) {
                        tokenPersister.persistToken((Token) token);
                    }
                }
            } catch (TrustException e) {
                String errorMessage = "Error in persisting tokens on module shut down..";
                log.error(errorMessage, e);
                throw new TrustException(errorMessage, e);
            } finally {
                readLock.unlock();
            }
        }

    }

    protected void processTokenExpiry() throws TrustException {
        readLock.lock();

        try {
            for (Iterator iterator = tokens.values().iterator(); iterator.hasNext();) {
                Token token = (Token) iterator.next();
                setIfTokenExpired(token);
            }
        } finally {
            readLock.unlock();
        }
    }

    public synchronized static String getIdFromSTR(OMElement str) {
        //ASSUMPTION:SecurityTokenReference/KeyIdentifier
        OMElement child = str.getFirstElement();
        if (child == null) {
            return null;
        }

        if (child.getQName().equals(new QName(WSConstants.SIG_NS, "KeyInfo"))) {
            return child.getText();
        } else if (child.getQName().equals(Reference.TOKEN)) {
            String uri = child.getAttributeValue(new QName("URI"));
            if (uri.charAt(0) == '#') {
                uri = uri.substring(1);
            }
            return uri;
        } else {
            return null;
        }
    }

    private void getTokenPersister() {
        if (MessageContext.getCurrentMessageContext() != null) {
            if (tokenPersister == null) {
                synchronized (this) {
                    if (tokenPersister == null) {
                        tokenPersister = (TokenPersister) MessageContext.getCurrentMessageContext()
                                .getConfigurationContext().getProperty(TokenPersister.TOKEN_PERSISTER_KEY);
                    }
                }
            }
        }
    }

    private void getThreshold() throws TrustException {
        try {
            //TODO:why there is no interface for issuer config? this is coupled to SAMLTokenIssuerConfig..
            if (maxInMemoryTokens == null) {
                synchronized (this) {
                    if (maxInMemoryTokens == null) {
                        if (MessageContext.getCurrentMessageContext() != null) {
                            SAMLTokenIssuerConfig issuerConfig = (SAMLTokenIssuerConfig)
                                    MessageContext.getCurrentMessageContext().getProperty(STSConstants.KEY_ISSUER_CONFIG);
                            maxInMemoryTokens = Integer.parseInt(issuerConfig.getPersisterPropertyMap().get(
                                    AbstractIssuerConfig.LOCAL_PROPERTY_THRESHOLD).toString());
                        }
                    }
                }
            }
            //if not provided in config, use a default value.
            if (maxInMemoryTokens == null) {
                maxInMemoryTokens = DEFAULT_IN_MEMORY_THRESHOLD;
            }
        } catch (NumberFormatException e) {
            String errorMessage = "errorReadingStorageThreshold";
            log.error(errorMessage, e);
            throw new TrustException(errorMessage, e);
        }
    }
    //this should be called inside a read lock
    private boolean isTokenExist(String tokenId) {
        return this.tokens.keySet().contains(tokenId) || persistedTokenIDList.contains(tokenId);
    }

    //this should not be called inside any locks.
    private void populatePersistedTokenIDs() {
        if (persistedTokenIDList.size() == 0) {
            synchronized (this) {
                if (persistedTokenIDList.size() == 0) {
                    if (tokenPersister.isTokensExist()) {
                        String[] persistedTokenIDs = tokenPersister.retrieveTokenIDs();
                        if (persistedTokenIDs != null) {
                            writeLock.lock();
                            try {
                                persistedTokenIDList.addAll(Arrays.asList(persistedTokenIDs));
                            } finally {
                                writeLock.unlock();
                            }
                        }
                    }
                }
            }
        }
    }
    //this should be called inside a read/write lock
    private void setIfTokenExpired(Token token) {
        if (token.getExpires() != null &&
            token.getExpires().getTime() < System.currentTimeMillis()) {
            token.setState(Token.EXPIRED);
        }
    }

    //we do not disable the token store completely, disable only for saml tokens.
    /*private boolean isStorageDisabled() {
        if (tokenStoreDisabled == null) {
            synchronized (this) {
                if (tokenStoreDisabled == null) {
                    if (MessageContext.getCurrentMessageContext() != null) {
                        SAMLTokenIssuerConfig issuerConfig = (SAMLTokenIssuerConfig)
                                MessageContext.getCurrentMessageContext().getProperty(
                                        STSConstants.KEY_ISSUER_CONFIG);
                        if (issuerConfig != null) {
                            tokenStoreDisabled = issuerConfig.isTokenStoreDisabled();
                            return issuerConfig.isTokenStoreDisabled();
                        }
                    }
                }
            }
        } else {
            return tokenStoreDisabled;
        }
        return false; //if not configured, default is false.
    }*/
}
