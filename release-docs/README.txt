======================================================
Apache Rampart-1.5.1 build  (Dec 23, 2010)

http://axis.apache.org/axis2/java/rampart
------------------------------------------------------

_______________________________
Contents of Binary Distribution
===============================

lib      - This directory contains all the libraries required by rampart
           in addition to the libraries available in the axis2 standard binary 
           release.
	   

rampart-1.5.1.mar   - WS-Security and WS-SecureConversation support for Axis2
rahas-1.5.1.mar     - STS module - to be used to add STS operations to a service

samples  - This contains samples on using Apache Rampart and configuring
           different components to carryout different WS-Sec* operations.

README.txt - This file

build.xml - Setup file to copy all jars to required places
____________
Installation
============

Using Ant
---------
Run ant script on extracted binary distribution and it will copy the required files to Axis2. You have to set the AXIS2_HOME system variable to point to your Axis2 binary distribution. 

Manual Installation
-------------------
You can copy the required libraries and module files manually. You need copy all the libraries in the lib directory of Rampart binary distribution to Axis2 lib directory and all the module files to in the modules directory of  Rampart binary distribution to Axis2 modules directory. 

Axis2 lib directory – AXIS2_HOME/lib (Standard binary distribution ) or axis2/WEB-INF/lib (WAR)

Axis2 modules directory – AXIS2_HOME/repository/modules (Standard binary distribution ) or axis2/WEB-INF/modules (WAR)


IMPORTANT: 
Before you build rampart from source distribution, you need provision for 
unlimited security jurisdiction as some of the test cases use key size of
256. So you need to download jce_policy-x_y_z.zip (relevant to your JDK version)
and replace the old jar files (local_policy.jar and US_export_policy.jar) in 
$JAVA_HOME/jre/lib/security. These files are listed in sun download site,
under the your JDK version as Java(TM) Cryptography Extension (JCE) Unlimited 
Strength Jurisdiction Policy Files.     

Bouncy castle jars are no longer shipped with Rampart binary distribution
due some patent issues.But as bouncy castle jars are necessary for Rampart, users 
will have to manually download and copy the bouncy castle jar corresponding the
relevant JDK. Bouncy castle jars can be downloaded from 
http://www.bouncycastle.org/latest_releases.html 

Adding bouncycastle as a security provider 

1.) Download bouncycastle according to your java version. You can download 
bouncycastle from the following link.
http://www.bouncycastle.org/latest_releases.html
2.) Add the bcprov-jdkXX-139.jar to your service's / client's classpath. 
3.) Add the following line to java.security file which can be found in JRE's 
lib/security directory as the last line.
security.provider.X=org.bouncycastle.jce.provider.BouncyCastleProvider

Test cases written for SAML 2.0 support requires endorsing the JDK's default JAXP 
implementation with Xerces(http://xerces.apache.org/mirrors.cgi#binary) and 
Xalan(http://xml.apache.org/xalan-j/downloads.html#latest-release). So before building Rampart from the
source distribution, you need to copy resolver-x.x.x.jar, serializer-x.x.x.jar, xercesImpl-x.x.x.jar 
and xml-apis-x.x.x.jar from the Xerces binary distribution and xalan-x.x.x.jar from the xalan binary 
distribution to the endorsed directory. If you are using Sun JDK, endorsed directory is located at 
$JAVA_HOME/jre/lib/endorsed.

When Rampart is deployed in a particular application server, please refer to the endorsing mechanism 
recommended for that server and endorse the JAXP implementation using the set of jars mentioned above. 

Before you try any of the samples make sure you

1.) Have the Axis2 standard binary distribution downloaded and extracted.
2.) Set the AXIS2_HOME environment variable
3.) Run ant from the "samples" directory to copy the required libraries and
    modules to relevant directories in AXIS2_HOME.

___________________
Crypto Notice
===================

   This distribution includes cryptographic software.  The country in 
   which you currently reside may have restrictions on the import, 
   possession, use, and/or re-export to another country, of 
   encryption software.  BEFORE using any encryption software, please 
   check your country's laws, regulations and policies concerning the
   import, possession, or use, and re-export of encryption software, to 
   see if this is permitted.  See <http://www.wassenaar.org/> for more
   information.

   The U.S. Government Department of Commerce, Bureau of Industry and
   Security (BIS), has classified this software as Export Commodity 
   Control Number (ECCN) 5D002.C.1, which includes information security
   software using or performing cryptographic functions with asymmetric
   algorithms.  The form and manner of this Apache Software Foundation
   distribution makes it eligible for export under the License Exception
   ENC Technology Software Unrestricted (TSU) exception (see the BIS 
   Export Administration Regulations, Section 740.13) for both object 
   code and source code.

   The following provides more details on the included cryptographic
   software:

   Apache Santuario : http://santuario.apache.org/
   Apache WSS4J     : http://ws.apache.org/wss4j/
   Bouncycastle     : http://www.bouncycastle.org/

___________________
Support
===================

Any problem with this release can be reported to Rampart mailing list
or in the JIRA issue tracker.

Mailing list subscription:
    java-dev-subscribe@axis.apache.org

Jira:
    http://issues.apache.org/jira/browse/RAMPART


Thank you for using Apache Rampart!

The Apache Rampart team.

[1] http://www.apache.org/dist/java-repository/xalan/jars/
