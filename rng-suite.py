import hashlib
import binascii
import random
import time
import ctypes
import hmac
import os
import getpass
from PIL import Image
rng = random.SystemRandom()

def init_key_generation(keylengthbits):
	if keylengthbits < 8:
		keylengthbits = 8
	elif keylengthbits % 8 != 0:
		keylengthbits += ( 8 - keylengthbits % 8)
	key = []
	iters = keylengthbits // 8
	for i in range(0,iters):
		key.append(format(rng.randint(0,255), '02x'))
	return "".join(key)

def byte_transpose(binarr):
	binarrlen = len(binarr)
	newbin = bytearray()
	for i in range(0,binarrlen,2):
		newbin.append(binarr[i+1])
		newbin.append(binarr[i])
	newbin2 = newbin[(binarrlen//2):] + newbin[:(binarrlen//2)]
	return newbin2

def bytearray_to_1_0(bytearr):
	new_array = []
	for i in range(0,len(bytearr)):
		if bytearr[i] >= 128:
			new_array.append(1)
		else:
			new_array.append(0)
	return new_array

class sha512_efb(object):
	def __init__(self, init_key):
		self.current_key = bytearray.fromhex(init_key)
		self.current_feedback = bytearray(hashlib.sha512(self.current_key).digest())
	def get_bytes_to_xor(self):
		self.current_key = self.current_key[-1:]+self.current_key[:-1]
		self.current_thing_to_hash = self.current_feedback+self.current_key
		self.current_feedback = bytearray(hashlib.sha512(self.current_thing_to_hash).digest())
		self.current_output_bytes = bytearray(hashlib.sha512(byte_transpose(self.current_thing_to_hash)).digest())
		return self.current_output_bytes
		
class rc4_simple(object):
	def __init__(self, init_key):
		self.S = []
		for i in range(0,256):
			self.S.append(i)
		j = 0
		for i in range(0,256):
			j = (j + self.S[i] + init_key[i%len(init_key)])%256
			self.S[i], self.S[j] = self.S[j], self.S[i]
		self.i = 0
		self.j = 0
	def get_bytes_to_xor(self):
		out = bytearray()
		for k in range(0,64):
			self.i = (self.i+1) % 256
			self.j = (self.j+ self.S[self.i]) % 256
			self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
			out.append(self.S[(self.S[self.i]+self.S[self.j])%256])
		return out
print('RNG test suite')
print('PRNGs Available:')
print('1: SHA-512 with 512-bit key and hash chain feedback')
print('2: RC4-drop4096')
opt = int(input('Option: '))
if opt == 1:
	csprng = sha512_efb(init_key_generation(512))
elif opt == 2:
	rc4k = int(input('1: Random key, 2: Manual key '))
	if rc4k == 1:
		rc4ks = int(input('RC4 key length in bits: '))
		csprng = rc4_simple(bytearray.fromhex(init_key_generation(rc4ks)))
	if rc4k == 2:
		rc4ks = str(input('RC4 key in HEX: '))
		csprng = rc4_simple(bytearray.fromhex(rc4ks))
	for i in range(0,64):
		csprng.get_bytes_to_xor()
fname = str(input("File name to save: "))
opt_save = int(input('1: Save to image (bmp), 2: Save to bin '))
if opt_save == 1:
	imgw = int(input("Image width: "))
	imgh = int(input("Image height: "))
	img_s_t = imgw, imgh
	imgnamereal = fname + ".bmp"
	img_to_save = Image.new("1",img_s_t)
	img_to_save_matrix = img_to_save.load()
	img_byte_size = imgw * imgh
	csprng_passes = (img_byte_size // 64) + min(1,(img_byte_size%64))
	barr = bytearray()
	for i in range(0,csprng_passes):
		barr.extend(csprng.get_bytes_to_xor())
	final_array = bytearray_to_1_0(barr)
	b_pos = 0
	for i in range(0, imgh):
		for j in range(0, imgw):
			img_to_save_matrix[i,j] = final_array[b_pos]
			b_pos += 1
	img_to_save.save(imgnamereal)
	img_to_save.close()
elif opt_save == 2:
	fname = fname + '.bin'
	file_to_save = open(fname,'wb')
	byte_amount = int(input('Amount of bytes to generate: '))
	csprng_passes = (byte_amount // 64) + min(1,(byte_amount%64))
	barr = bytearray()
	for i in range(0,csprng_passes):
		barr.extend(csprng.get_bytes_to_xor())
	file_to_save.write(barr)
	file_to_save.close()
#for i in range(0,8):
#	print(bytes.decode(binascii.hexlify(csprng.get_bytes_to_xor())))
