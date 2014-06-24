tpm-malcrypt
============

An example malicious payload controller and obfuscator assisted by TPM-protected keys.

tpm-keyextract
--------------

Detect a TPM on a client and create a new encryption keypair using standard protections.
Return the public key component to be transmitted back to a encrypted PE generator.

malcrypt
--------

Using an input public key and input malicious payload, generate and return a self-decrypting
PE that decrypts and executes in-memory.

Although the output PE can be executed on any machine, only a *target* machine will have
the private key pair in it's crypto-store. Thus only a *target* machine will decrypt and 
executed the original input payload. 

The malcrypt application involves several components and processes:
  * Target OS crypto-store accesses.
  * An in-memory decryption/execution stub.
  * An encryptor and PE section injector.

For the crypto-store access, malcrypt assumes the input public key was created with no or
known controls by `tpm-keyextract`. The security of the private key is not critical to
malcrypt if a TPM was used to generate the key pair. Malcrypt intends to limit the 
execution of the input payload to a *target* system. There are trusted computing concerns
related to proving a TPM was used to create the keypair, but they are outside the scope
of the example PoC implementation.

