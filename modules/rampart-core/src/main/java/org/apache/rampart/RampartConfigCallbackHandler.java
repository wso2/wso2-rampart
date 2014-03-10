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

import org.apache.rampart.policy.model.RampartConfig;

/**
 * Callback handler interface to update Rampart Configuration dynamically. Updater class should 
 * implement this interface and should be registered using the Rampart Configuration as below.
 *  
 * Example: 
 * <PRE>
 *  <ramp:RampartConfig xmlns:ramp="http://ws.apache.org/rampart/policy"> 
 *   <ramp:rampartConfigCallbackClass>o.a.r.ConfigUpdater</ramp:rampartConfigCallbackClass>
 *    ...
 *   </ramp:RampartConfig>
 *  </PRE>
 */

public interface RampartConfigCallbackHandler {
    
    public void update(RampartConfig rampartConfig);        
    
}