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

import java.util.Vector;

/**
 * Callback handler interface to allow different implementations of policy based results validation.
 * Default implementation is <code>org.apache.rampart.PolicyBasedResultsValidator</code>.
 * Custom implementations could be provided in rampart config as shown in below example.
 *  
 * Example: 
 * <PRE>
 *  <ramp:RampartConfig xmlns:ramp="http://ws.apache.org/rampart/policy"> 
 *   <ramp:policyValidatorCbClass>xx.yy.CustomPolicyValidator</ramp:policyValidatorCbClass>
 *    ...
 *   </ramp:RampartConfig>
 *  </PRE>
 */

public interface PolicyValidatorCallbackHandler {
   /**
    * Validate policy based results.
    * 
    * @param data validator data
    * @param results policy based ws-security results 
    * @throws RampartException Rampart exception
    */ 
   public abstract void validate(ValidatorData data, Vector results) throws RampartException;

}