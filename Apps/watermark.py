#!/usr/bin/env python3
'''
	Library used for watermarking operations.
'''

from PIL import Image


def applyWM(path,wm):
	img=Image.open(path)
	pix=img.load()

	# Index for k bit in watermark
	k=0

	for i in range(img.size[0]):
		for j in range(img.size[1]):

			# Repeat the watermark bits
			if (wm >> k) == 0:
				k=0 

			if (pix[i,j][0] & 1) != ((wm >> k) & 1):
				# Invert last bit to match watermark bit
				pix[i,j] = (pix[i,j][0] ^ 1, pix[i,j][1], pix[i,j][2])
			k+=1

	return img


def checkWM(path,wm):
	img=Image.open(path)
	pix=img.load()

	# Index for k bit in watermark
	k=0

	# Checked watermark
	hits=0

	for i in range(img.size[0]):
		for j in range(img.size[1]):

			# Repeat the watermark bits
			if (wm >> k) == 0:
				k=0 

			wm_bit = ((wm >> k) & 1)
			if (pix[i,j][0] & 1) == wm_bit:
				hits +=1

			k+=1

	img.close()

	return hits/(img.size[0]*img.size[1])


'''
TESTING
'''
def testProgram(pathIN,pathTMP,wm):
	i = applyWM(pathIN,wm)
	i.save(pathTMP)
	i.close()
	print("Checked percentage:",checkWM(pathTMP,wm))
