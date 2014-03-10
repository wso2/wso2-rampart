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


public class RahasConstants {

    public final static int VERSION_05_02 = 1;
    public final static int VERSION_05_12 = 2;
    public final static int VERSION_08_02 = 3;

    /**
     * WS-Trust 2005 Feb namespace
     */
    public final static String WST_NS_05_02 = "http://schemas.xmlsoap.org/ws/2005/02/trust";

    /**
     * WS-SX Namespace
     */
    public final static String WST_NS_05_12 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    public final static String WST_NS_08_02 = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";

    public final static String WST_PREFIX = "wst";
    public final static String WST14_PREFIX = "wst14";
    public final static String SAML_PREFIX = "saml";
    
    public final static String WSP_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public final static String WSP_PREFIX = "wsp";

    public static class LocalNames {
        public static final String REQUEST_SECURITY_TOKEN = "RequestSecurityToken";
        public static final String REQUEST_SECURITY_TOKEN_RESPONSE = "RequestSecurityTokenResponse";
        public static final String REQUEST_TYPE = "RequestType";
        public static final String TOKEN_TYPE = "TokenType";
        public static final String REQUESTED_PROOF_TOKEN = "RequestedProofToken";
        public static final String
                REQUEST_SECURITY_TOKEN_RESPONSE_COLLECTION = "RequestSecurityTokenResponseCollection";
        public final static String BINARY_SECRET = "BinarySecret";
        public final static String VALIDATE_TARGET = "ValidateTarget";
        public final static String RENEW_TARGET = "RenewTarget";
        
       /* <wst:RequestSecurityTokenResponse>
        * <wst:TokenType>http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Status</wst:TokenType>
        * <wst:Status>
        * <wst:Code>http://schemas.xmlsoap.org/ws/2005/02/trust/status/valid</wst:Code>
        * </wst:Status> ... </wst:RequestSecurityTokenResponse>"
        */
        public static final String STATUS = "Status";
        public static final String CODE = "Code";

        // Added for supporting WS-Trust 1.4
        public static final String ACTAS = "ActAs";
        public final static String SAML2_NAMEID = "NameID";
        public final static String SAML1_NAMEID = "NameIdentifier";
        public final static String SUBJECT ="Subject";
        public final static String ATTR_STMT = "AttributeStatement";
        public final static String SAML1_AUTH_STMT = "AuthenticationStatement";
        public final static String ATTR = "Attribute";
        public final static String NAME_ATTR = "Name";
        public final static String ATTR_VALUE = "AttributeValue";
    }

    public static class IssuanceBindingLocalNames {
        public static final String REQUESTED_SECURITY_TOKEN = "RequestedSecurityToken";
        public static final String COMPUTED_KEY_ALGO = "ComputedKeyAlgorithm";
        public static final String COMPUTED_KEY = "ComputedKey";
        public static final String REQUESTED_ATTACHED_REFERENCE = "RequestedAttachedReference";
        public static final String REQUESTED_UNATTACHED_REFERENCE = "RequestedUnattachedReference";
        public static final String KEY_SIZE = "KeySize";
        public static final String KEY_TYPE = "KeyType";
        public static final String ENTROPY = "Entropy";
        public static final String APPLIES_TO = "AppliesTo";
        public static final String LIFETIME = "Lifetime";
        public static final String CLAIMS = "Claims";
       
    }

    public static class CancelBindingLocalNames {
        public static final String REQUESTED_TOKEN_CANCELED = "RequestedTokenCancelled";
        public static final String CANCEL_TARGET = "CancelTarget";
        public static final String URI = "URI";
    }

    //Key types
    public static final String KEY_TYPE_SYMM_KEY = "/SymmetricKey";
    public static final String KEY_TYPE_PUBLIC_KEY = "/PublicKey";
    public static final String KEY_TYPE_BEARER = "/Bearer";

    //Attr values
    public static final String BIN_SEC_TYPE_NONCE = "/Nonce";

    //ComputedKey algos
    public static final String COMPUTED_KEY_PSHA1 = "/CK/PSHA1";

    //  RequestTypes
    public static final String REQ_TYPE_ISSUE = "/Issue";
    public static final String REQ_TYPE_VALIDATE = "/Validate";
    public static final String REQ_TYPE_RENEW = "/Renew";
    public static final String REQ_TYPE_CANCEL = "/Cancel";

    //RST actions
    public static final String RST_ACTION_ISSUE = "/RST" + REQ_TYPE_ISSUE;
    public static final String RST_ACTION_VALIDATE = "/RST" + REQ_TYPE_VALIDATE;
    public static final String RST_ACTION_RENEW = "/RST" + REQ_TYPE_RENEW;
    public static final String RST_ACTION_CANCEL = "/RST" + REQ_TYPE_CANCEL;
    public static final String RST_ACTION_SCT = "/RST/SCT";
    public static final String RST_ACTION_CANCEL_SCT = "/RST/SCT" + REQ_TYPE_CANCEL;

    //RSTR actions
    public static final String RSTR_ACTION_ISSUE = "/RSTR" + REQ_TYPE_ISSUE;
    public static final String RSTR_ACTION_VALIDATE = "/RSTR" + REQ_TYPE_VALIDATE;
    public static final String RSTR_ACTION_RENEW = "/RSTR" + REQ_TYPE_RENEW;
    public static final String RSTR_ACTION_CANCEL = "/RSTR" + REQ_TYPE_CANCEL;
    public static final String RSTR_ACTION_SCT = "/RSTR/SCT";
    public static final String RSTR_ACTION_CANCEL_SCT = "/RSTR/SCT" + REQ_TYPE_CANCEL;
    
    //Status codes
    public static final String STATUS_CODE_VALID = "/status/valid";
    public static final String STATUS_CODE_INVALID = "/status/invalid";
    
    public static final String TOK_TYPE_STATUS = "/RSTR/Status";

    //Token types
    public static final String TOK_TYPE_SAML_10 = "http://docs.oasis-open.org/wss/" +
                                                  "oasis-wss-saml-token-profile-1.1#SAMLV1.1";

    public static final String TOK_TYPE_SAML_20 = "http://docs.oasis-open.org/wss/" +
                                                  "oasis-wss-saml-token-profile-1.1#SAMLV2.0";

    //Token Namespaces
    public static final String TOK_TYPE_SAML_10_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
    public static final String TOK_TYPE_SAML_20_NS = "urn:oasis:names:tc:SAML:2.0:assertion";


    //Attrs
    public static final String ATTR_TYPE 	        = "Type";
    public static final String ATTR_CLAIMS_DIALECT 	= "Dialect";

    //Constants required for SAML2 assertion generation
    public final static String X509_CERT ="X509Certificate";
    public final static String USERNAME = "username";

    //Constants required for SubjectConfirmation methods
    public static final String SAML11_SUBJECT_CONFIRMATION_HOK = "urn:oasis:names:tc:SAML:1.0:cm:" +
                                                          "holder-of-key";
    public static final String SAML11_SUBJECT_CONFIRMATION_BEARER = "urn:oasis:names:tc:SAML:1.0:cm:bearer";

    public static final String SAML11_SUBJECT_CONFIRMATION_SENDER_VOUCHES = "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches";

    public static final String SAML20_SUBJECT_CONFIRMATION_HOK = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

 // Namespaces used in SAML1.0 and SAML2.0
    public final static String  NS_SAML_10 = "urn:oasis:names:tc:SAML:1.0:assertion" ;
    public final static String NS_SAML_20 = "urn:oasis:names:tc:SAML:2.0:assertion";
    
    public final static String PASSIVE_STS_RST = "passiveSTSRST";
    public static final String SAML20_SUBJECT_CONFIRMATION_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public static final String SAML20_SUBJECT_CONFIRMATION_SENDER_VOUCHES = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";
}
