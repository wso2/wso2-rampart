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

import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.Token;
import org.apache.rahas.TokenPersister;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * This implements a file system based non-volatile storage mechanism for retired security tokens.
 * This is accessed by/through token persister which handles concurrency with read/write locks.
 * Hence read/write locks are not incorporated here.
 */
public class FSBasedRetiredTokenPersister implements TokenPersister {

    private static Log log = LogFactory.getLog(FSBasedRetiredTokenPersister.class);

    protected String securityTokenStorageFilePath = null;

    protected int maxTokensInMemory;
    
    private MessageContext msgCtx = null;

    protected TokenStorage tokenStorage = null;

    private Thread persistanceThread = null;

    private final CharSequence tokenExtension = ".token";

    public boolean isTokensExist() {
        File tokensDir = new File(securityTokenStorageFilePath);
        String[] children = tokensDir.list();
        if (children != null && children.length != 0) {
            for (String child : children) {
                if (child.contains(tokenExtension)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isTokenExist(String tokenID) {
        File tokensDir = new File(securityTokenStorageFilePath);
        String[] children = tokensDir.list();
        if (children != null && children.length != 0) {
            for (String child : children) {
                if (child.contains(tokenExtension)) {
                    String childID = child.split("\\.")[0];
                    if (tokenID.equals(childID)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public synchronized void persistTokens(Token[] retiredTokens) throws TrustException {
        for (Token retiredToken : retiredTokens) {
            persistToken(retiredToken);
        }
    }

    public synchronized void persistToken(Token token) throws TrustException {
        try {
            FileOutputStream outTokenFile =
                    new FileOutputStream(securityTokenStorageFilePath + File.separator + token.getId() +
                                         tokenExtension.toString());
            ObjectOutputStream tokenObjOutStream = new ObjectOutputStream(outTokenFile);
            tokenObjOutStream.writeObject(token);
            tokenObjOutStream.close();

        } catch (FileNotFoundException e) {
            String errorMessage = "File can not be found/created to persist the token.";
            throw new TrustException(errorMessage, e);

        } catch (IOException e) {
            String errorMessage = "I/O error while creating output stream for token";
            throw new TrustException(errorMessage, e);
        }
    }

    public Token[] retrieveTokens() {
        return new Token[0];  //To change body of implemented methods use File | Settings | File Templates.
    }

    public Token retrieveToken(String tokenId) throws TrustException {
        Token retrievedToken = null;
        try {
            FileInputStream inTokenFile = new FileInputStream((securityTokenStorageFilePath +
                                                               File.separator + tokenId) + tokenExtension.toString());
            ObjectInputStream tokenObjInStream = new ObjectInputStream(inTokenFile);
            retrievedToken = (Token) tokenObjInStream.readObject();
            tokenObjInStream.close();

        } catch (FileNotFoundException e) {
            String errorMessage = "Stored token file can not be found.";
            throw new TrustException(errorMessage, e);

        } catch (IOException e) {
            String errorMessage = "I/O error while creating input stream for token";
            throw new TrustException(errorMessage, e);

        } catch (ClassNotFoundException e) {
            throw new TrustException(e.getMessage(), e);

        }
        return retrievedToken;
    }

    public String[] retrieveTokenIDs() {
        File tokensDir = new File(securityTokenStorageFilePath);
        String[] children = tokensDir.list();
        if (children.length == 0) {
            return null;
        } else {
            String[] persistedTokenIDs = new String[children.length];
            int index = 0;
            for (String child : children) {
                if (child.contains(tokenExtension)) {
                    persistedTokenIDs[index] = child.split("\\.")[0];
                    index++;
                }
            }
            return persistedTokenIDs;
        }
    }

    public void updateToken(Token token) throws TrustException {
        try {
            //delete existing token
            deleteToken(token.getId());
            //persist the updated token
            persistToken(token);
        } catch (TrustException e) {
            String errorMessage = "Error in updating the token.";
            log.error(errorMessage);
            throw new TrustException(errorMessage, e);
        }
    }

    public void deleteToken(String tokenId) throws TrustException {
        File tokenToDelete = new File(securityTokenStorageFilePath + File.separator +
                                      tokenId + tokenExtension.toString());
        boolean success = tokenToDelete.delete();
        if (!success) {
            throw new TrustException("Token could not be deleted.");
        }
    }

    public void setConfiguration(AbstractIssuerConfig config) throws TrustException {
        this.securityTokenStorageFilePath = (String) ((SAMLTokenIssuerConfig) config).getPersisterPropertyMap().get(
                AbstractIssuerConfig.LOCAL_PROPERTY_STORAGE_PATH);
        if (securityTokenStorageFilePath == null) {
            String errorMessage = "Storage path is not set in configuration.";
            log.error(errorMessage);
            throw new TrustException(errorMessage);
        }
        try {
            this.maxTokensInMemory = Integer.parseInt(
                    (String) ((SAMLTokenIssuerConfig) config).getPersisterPropertyMap().get(
                    AbstractIssuerConfig.LOCAL_PROPERTY_THRESHOLD));
        } catch (NumberFormatException e) {
            String errorMessage = "errorReadingStorageThreshold";
            log.error(errorMessage);
            throw new TrustException(errorMessage, e);
        }
    }

    public void setMessageContext(MessageContext msgContext) {
        this.msgCtx = msgContext;
    }

    public void notifyPersistence() {

        if (persistanceThread == null) {
            persistanceThread = new Thread(this);
            persistanceThread.start();
        }
    }

    /**
     * Obtain the list of tokens that are to be persisted.
     * TODO:this is made public to be used in tests. Should make this protected or private
     * @param inMemoryTokens list of tokens currently resides in memory.
     * @return List of tokens to be sent to persistence.
     */
    public List<String> getRetiredTokens(List<Token> inMemoryTokens) {

        //get 'token id', 'created date' mapping
        Map<String, Date> tokensMap = new HashMap<String, Date>();

        //we retire only those tokens which are marked as persistenceEnabled
        for (Token inMemoryToken : inMemoryTokens) {
            if (inMemoryToken.isPersistenceEnabled()) {
                tokensMap.put(inMemoryToken.getId(), inMemoryToken.getCreated());
            }
        }

        //get a list of token ids
        List<String> keyList = new ArrayList(tokensMap.keySet());
        //get a list of created dates
        List<Date> valueList = new ArrayList(tokensMap.values());

        Object[] datesArray = valueList.toArray();

        //sort dates array
        Arrays.sort(datesArray);

        //obtain the mapping of retired token id and created date
        Map<String, Object> retiredTokenIDMap = new LinkedHashMap<String, Object>();

        //we retire 1/4 th of the max in memory capacity at once
        for (int i = 0; i < (maxTokensInMemory / 4); i++) {
            retiredTokenIDMap.put(keyList.get(valueList.indexOf(datesArray[i])), datesArray[i]);
        }

        List<String> retiredTokensIDList = new ArrayList<String>();

        //construct the retired tokens list
        for (String tokenID : retiredTokenIDMap.keySet()) {
            retiredTokensIDList.add(tokenID);
        }

        return retiredTokensIDList;
    }

    /**
     * When an object implementing interface <code>Runnable</code> is used
     * to create a thread, starting the thread causes the object's
     * <code>run</code> method to be called in that separately executing
     * thread.
     * <p/>
     * The general contract of the method <code>run</code> is that it may
     * take any action whatsoever.
     *
     * @see Thread#run()
     */
    public void run() {
        //get token store
        if (tokenStorage == null) {
            tokenStorage = (TokenStorage) msgCtx.getConfigurationContext().getProperty(
                    TokenStorage.TOKEN_STORAGE_KEY);
        }
        try {
            //get all tokens from token storage
            List<Token> inMemoryTokens = tokenStorage.getStorageTokens();

            //process and get a list of tokens' ids to be persisted
            List<String> persistingTokens = getRetiredTokens(inMemoryTokens);

            //handle persistence of tokens -managed in storage itself.
            tokenStorage.handlePersistence(persistingTokens);
        } catch (TrustException e) {
            String errorMessage = "Error occurred during persistence process.";
            log.error(errorMessage, e);
        } finally {
            persistanceThread = null;
        }
    }
    
}
