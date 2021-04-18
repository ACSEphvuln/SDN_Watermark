#!/usr/bin/env python3
'''
	Library used for watermarking operations.
'''

from PIL import Image

class Watermarker():

	PREAMBLE = 0xdeadbeef

	def __init__(self,path):
		self.i = 0
		self.j = 0
		self.img=Image.open(path)
		self.pix=self.img.load()

	def __writeToImg(self,msg,n):
		k=0
		# Write preamble
		while k < n:
			if (self.pix[self.i,self.j][0] & 1) != ((msg >> k) & 1):
				# Invert last bit to match preamble bit
				self.pix[self.i,self.j] = (self.pix[self.i,self.j][0] ^ 1, self.pix[self.i,self.j][1], self.pix[self.i,self.j][2])
			k+=1
			self.j+=1
			if self.j >= self.img.size[1]:
				self.j = 0
				self.i +=1

	def __readFromImg(self,n):
		k=0
		msg = 0
		# Write preamble
		while k < n:
			msg += (self.pix[self.i,self.j][0] & 1) << k
			k+=1
			self.j+=1
			if self.j >= self.img.size[1]:
				self.j = 0
				self.i +=1
		return msg


	def applyWM(self,wm):

		wmsize = len(str(wm))

		if wmsize > 2**16:
			print("Watermark msg too big.")

		# Preamble + size + actual watermark
		if (8+2+wmsize)*8 > self.img.size[0]*self.img.size[1]:
			print("Image size too small for watermark length.")

		self.i = 0
		self.j = 0

		self.__writeToImg(Watermarker.PREAMBLE,64)
		self.__writeToImg(wmsize,16)
		self.__writeToImg(wm,wmsize*8)

		return self.img


	def checkWM(self):

		self.i = 0
		self.j = 0
		# Index for k bit in watermark
		k=0

		# Check preamble
		if self.__readFromImg(64) != Watermarker.PREAMBLE:
			print("No watermark")
			return 0

		# Read size
		wmsize = self.__readFromImg(16)
		if (8+2+wmsize)*8 > self.img.size[0]*self.img.size[1]:
			print("Corrupted watermark")
			return 0

		# Read watermark
		wm = self.__readFromImg(wmsize*8)

		return wm

'''
TESTING
'''
if __name__ == '__main__':
	# import binascii
	pathIN = './Sample_Images/Original/lena.png'
	pathTMP = './Sample_Images/Test/lena.png'
	# wm = int(binascii.hexlify(b'test'))
	wm = 1337
	w = Watermarker(pathIN)
	i = w.applyWM(wm)
	i.save(pathTMP)

	w = Watermarker(pathTMP)
	print("Watermark in file:",w.checkWM())
