********************************************************************************
**************************** Apache Rampart Samples ****************************
********************************************************************************

This directory contains three sub directories:

    - basic - A set of samples that uses basic rampart configuration using 
    	          parameters

    - policy - A set of samples that uses rampart with WS-SecurityPolicy
    
    - keys   - The keystore files that contains the keys used by the samples

Please use Apache Ant with the build.xml file available here to copy all jars
and mars to required places.

    - Please copy log4j.jar to AXIS2_HOME/lib directory before trying out samples.

    - Please follow the instructions on endorsing the default JAXP implementation
      available in README.txt of this distribution before invoking 
      Sample 08.(Issuing a SAML 2.0 Token)
