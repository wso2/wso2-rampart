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

import org.apache.ws.security.WSPasswordCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.IOException;

import net.sf.jpam.Pam;
import net.sf.jpam.PamReturnValue;

public class JPAMCallbackHandler implements CallbackHandler {

    public void handle(Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            // When the server side need to authenticate the user
            WSPasswordCallback pwcb = (WSPasswordCallback) callbacks[i];
            if (pwcb.getUsage() == WSPasswordCallback.USERNAME_TOKEN_UNKNOWN) {
                Pam pam = new Pam();
                PamReturnValue ret = pam.authenticate(pwcb.getIdentifer(), pwcb
                        .getPassword());
                if (ret.equals(PamReturnValue.PAM_SUCCESS)) {
                    return;
                } else {
                    throw new IOException("check failed");
                }

            }
        }
    }

}
