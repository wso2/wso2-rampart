Sign and Encrypt messages with multiple X509 certficates with multiple supporting tokens.

An AsymmetricBinding is used.

Multiple Supporting Tokens used each having different X509 certs for signature and encryption.

X509Token asserton carries a RampartConfig assertion to specify the keys that needs to be used to sign/encrypt
EncryptedElements/EncryptedParts/SignedElements/SignedParts

Algorithm suite is TripleDesRsa15

Note that {http://ws.apache.org/rampart/policy}RampartConfig assertion provides
additional information required to secure the message.