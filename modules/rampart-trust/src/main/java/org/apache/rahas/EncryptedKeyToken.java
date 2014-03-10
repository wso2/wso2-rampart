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

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Date;

import org.apache.axiom.om.OMElement;

/**
 * This token is used store Encrypted Key Tokens. This token contains the
 * SHA1 value of the Encrypted Key.
 *
 * These tokens are stored using the storage mechanism provided via the 
 * <code>TokenStorage</code> interface.
 * @see org.apache.rahas.TokenStorage
 *
 */
public class EncryptedKeyToken extends Token {
	
    /**
     * SHA1 value of the encrypted key
     */
    private String sha;

    public EncryptedKeyToken(){
        super();
    }
	
	public EncryptedKeyToken (String id,Date created, Date expires) {
		super(id,created,expires);
	}
	
	public EncryptedKeyToken (String id, OMElement tokenElem, 
			                    Date created, Date expires)throws TrustException{
		super(id,tokenElem,created,expires);
	}
	
	/**
	 * @param sha SHA1 of the encrypted key
	 */
	public void setSHA1(String sha) {
		this.sha = sha;
	}
	
	/** 
	 * @return SHA1 value of the encrypted key 
	 */
	public String getSHA1() {
		return sha;
	}

    public void writeExternal(ObjectOutput out)
        throws IOException {

        super.writeExternal(out);
        out.writeObject(this.sha);
    }

    public void readExternal(ObjectInput in)
        throws ClassNotFoundException, IOException {

        super.readExternal(in);
        this.sha = (String)in.readObject();

    }


}
