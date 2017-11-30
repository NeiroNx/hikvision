#!/usr/bin/python3
import os, sys

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

	headerChecksum = int.from_bytes(header[4:8], byteorder='little')
	headerLength = int.from_bytes(header[8:12], byteorder='little')
	numFiles = int.from_bytes(header[12:16], byteorder='little')
	
	lenFileInfo = (headerLength - 64) // numFiles
	
	mas = []
	for i in range(64, len(header), lenFileInfo):
		mas.append(header[i:i+lenFileInfo])
	
	filesInfo = []
	for i in mas:
		temp = []
		temp.append((i[:32:].rstrip(b'\x00')).decode('utf-8'))    # fileName
		temp.append(int.from_bytes(i[32:36], byteorder='little')) # fileOffset 
		temp.append(int.from_bytes(i[36:40], byteorder='little')) # fileSize
		#temp.append(int.from_bytes(i[40:44], byteorder='little')) # fileChecksum
		filesInfo.append(temp)
	

	return filesInfo

def cutFiles(firmware):
	name = firmware
	firm = open(firmware, 'rb').read()
	lenHeaderEnc = firm[:16]
	lenHeaderDec = int.from_bytes(xorHeader(lenHeaderEnc)[8:12], byteorder='little')
	headerEnc = firm[:lenHeaderDec:]
	headerDec = xorHeader(headerEnc)
	os.mkdir(name + '_unpacked')
	os.chdir(name + '_unpacked')
	file = open ('header', 'wb'); file.write(headerDec); file.close()

	filesInfo = parseHeader(headerDec)

	for x in filesInfo:
		tempFile = firm[x[1]:x[1]+x[2]:]
		file = open (x[0], 'wb')
		file.write(tempFile)
		file.close()

	print('Firmware', name, 'unpacked.')
	return 1


def main():
	if len(sys.argv) > 1:
		cutFiles (sys.argv[1])
	else:
		print("Hikvision IPC firmware unpacker (R0 series).\n\n\t Example: python3 unpackFirmware.py /path/to/target_digicap.dav")

if __name__ == "__main__":
    main()



	









