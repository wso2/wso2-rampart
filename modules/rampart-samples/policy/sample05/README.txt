WS-Trust - RST - Resquest Security Token Service - Issuing a SAML token - issuing a token

When using this sample with the TCPMon to monitor the soap messages, you have to use the 
correct URL in the client code before build the sample 05.

There is a known bug in OpenSAML-1.1.jar, which is used for implementing SAML 1.1 support in Rampart.
So before you run this sample, please download the patched OpenSAML jar from here[1], and replace it 
with the OpenSAML-1.1.jar in your $AXIS2_HOME/lib.

[1] - http://dist.wso2.org/maven2/opensaml/opensaml/1.1.406/opensaml-1.1.406.jar  

