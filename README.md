tpm-malcrypt
============

An example malicious payload controller and obfuscator assisted by TPM-protected keys.

## malcrypter

This is the offline (server-side) component that generates the executed payload from the 
decrypter stub and your choice of encrypted payload.

### Installation:

  1. Grab PyDbg from: http://www.lfd.uci.edu/~gohlke/pythonlibs/
  2. Within CMD: `SET VS90COMNTOOLS=%VS120COMNTOOLS%`
  3. `pip install pefile pycrypto`

## malcrypt

This is a Windows VS2013 solution containing two projects. The logic can be rewritten on OSX 
or Linux, depending on the intended target.

### Part 1: tpm-keyextract

Detect a TPM on a client and create a new encryption keypair using standard protections.
Return the public key component to be transmitted back to a encrypted PE generator.

### Part 2: malcrypt

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

References
----------

  * The original TPM Malware: https://www.cs.utexas.edu/~adunn/pubs/malware-tpm.pdf
  * DEF CON 22 WAGONBED: https://www.defcon.org/html/defcon-22/dc-22-speakers.html#Datko
  * Windows PCP Tool: http://research.microsoft.com/en-us/downloads/74c45746-24ad-4cb7-ba4b-0c6df2f92d5d/

License
-------

MIT and Microsoft MSR-LA.
