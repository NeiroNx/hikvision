#!/usr/bin/python3
import os, sys, shutil, hashlib
from struct import pack, unpack
from Cryptodome.Util.Padding import pad
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF1
from Cryptodome.Hash import MD5

def sar(n, pos):
    tmp = bin(n)[2:]
    while len(tmp) < 8: tmp = '0%s' %(tmp)
    b = tmp[0]
    tmp = bin(n >> pos)[2:]
    while len(tmp) < 8: tmp = '%s%s' %(b,tmp)
    return int(tmp,2)

def Decode(BufSrc, Len):
    Result = []
    if Len > 0:
        Key = b'\xBA\xCD\xBC\xFE\xD6\xCA\xDD\xD3\xBA\xB9\xA3\xAB\xBF\xCB\xB5\xBE'
        for i in range(Len):
            Result.append(BufSrc[i] ^ Key[(i + sar(i, 4)) & 15])
    return bytes(Result)

def xorHeader (FileName, ReadLen=0, AsIT=True):
    if ReadLen > 0:
        DstBuf = FileName
        if AsIT: DstBuf = Decode(DstBuf, ReadLen)
        return DstBuf
    else:
        DstBuf = FileName
        if AsIT: DstBuf = Decode(DstBuf, len(DstBuf))
        return DstBuf

def parseHeader (header):
	numFiles = unpack('<i',header[12:16])
	lenFileInfo = (len(header) - 64) // numFiles
	mas = []
	for i in range(64, len(header), lenFileInfo):
		mas.append(header[i:i+lenFileInfo])
	filesNames = []
	for i in mas:
		filesNames.append((i[:32:].rstrip(b'\x00')).decode('utf-8'))    # fileName
	return filesNames

def calcFileChecksum(file):
	checkSum = 0
	for i in file:
		checkSum += i
	return checkSum

def crypt(_cfgUpgSecPls, flag):
	#gen key
	passphrase = b'h@k8807H$Z5998' 
	passphrase = passphrase.ljust (31, b'\x00')
	salt = b'HangZhou'
	key = PBKDF1(passphrase, salt, 16, 2, MD5)
	key += PBKDF1(key + passphrase, salt, 16, 2, MD5)
	cipher = AES.new(key, AES.MODE_ECB)
	_cfgUpgSecPls = pad(_cfgUpgSecPls, 16)
	if flag == 'd':
		#dec _cfg
		dec_cfgUpgSecPls = cipher.decrypt(_cfgUpgSecPls)
		return dec_cfgUpgSecPls
	else:
		#enc _cfg
		enc_cfgUpgSecPls = cipher.encrypt(_cfgUpgSecPls)
		return enc_cfgUpgSecPls

def repackFirm(unpackedFirm):
	os.chdir(unpackedFirm)
	decHeader = open('header', 'rb').read()
	filesNames = parseHeader(decHeader)
	enc_cfgUpgSecPls = open('_cfgUpgSecPls', 'rb').read()
	fileOffset = len(decHeader) + len(enc_cfgUpgSecPls)
	decHeader = decHeader[:108]
	#dec _cfgSec
	magic = enc_cfgUpgSecPls[:4] 
	enc_cfgUpgSecPls = enc_cfgUpgSecPls[4:]
	dec_cfgUpgSecPls = crypt(enc_cfgUpgSecPls, 'd')
	dec_cfgUpgSecPls = dec_cfgUpgSecPls[:204]

	os.remove('header')
	
	#change files info
	for fileName in filesNames:
		if fileName != 'header' and fileName != '_cfgUpgSecPls':
			file = open( fileName, 'rb').read()
			sha = hashlib.new('sha')
			sha.update(file)
			fileSHA = sha.digest()
			fileName = fileName.encode('utf-8').ljust (32, b'\x00')
			fileSize = len(file)
			fileChecksum = calcFileChecksum(file)
			dec_cfgUpgSecPls += fileName + fileSHA + pack('<l', fileSize) + pack('<l', fileOffset).ljust (20, b'\x00')
			decHeader += fileName + pack('<l', fileOffset) + pack('<l', fileSize) + pack('<l', fileChecksum)
			fileOffset += fileSize
	imageSize = fileOffset
	dec_cfgUpgSecPls = bytearray(dec_cfgUpgSecPls)
	decHeader = bytearray(decHeader)
	#change sha of _cfgSec
	sha = hashlib.new('sha')
	sha.update(dec_cfgUpgSecPls[24:])
	dec_cfgUpgSecPls[4:24] = sha.digest()
	#enc _cfgSec
	dec_cfgUpgSecPls = bytes(dec_cfgUpgSecPls)
	enc_cfgUpgSecPls = crypt(dec_cfgUpgSecPls, 'e')
	enc_cfgUpgSecPls = (magic + enc_cfgUpgSecPls).ljust (int.from_bytes(decHeader[100:104], byteorder='little'), b'\x00')
	#change header
	decHeader[32:36] = pack('<l', imageSize)
	decHeader[104:108] = pack('<l', calcFileChecksum(enc_cfgUpgSecPls))
	decHeader[4:8] = pack('<l', calcFileChecksum(decHeader[12:]))
	decHeader = bytes(decHeader)
	encHeader = xorHeader(decHeader)

	_cfgUpgSecPls = open('_cfgUpgSecPls', 'wb')
	_cfgUpgSecPls.write(enc_cfgUpgSecPls);_cfgUpgSecPls.close()

	#concat files
	imageName = 'custom.dav'
	newImage = open (imageName, 'wb')
	newImage.write(encHeader)

	for file in filesNames:
		shutil.copyfileobj(open(file, 'rb'), newImage)
		os.remove(file)
	
	newImage.close()
	os.chdir("..")
	os.rename(unpackedFirm,imageName)
	print("New custom.dav image created.")
	return 1

def main():
	if len(sys.argv) > 1:
		repackFirm(sys.argv[1])
	else:
		print("Hikvision IPC firmware repacker (R0 series).\n\n\t Example: python3 repackFirmware.py /path/to/unpacked_firmware_folder")

if __name__ == "__main__":
    main()













