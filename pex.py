import pefile
import peutils
import time
import sys
import pexutils

filename = sys.argv[1]
pexutils.getAvSignature(filename)

pe = pefile.PE(filename)
timestamp = pe.FILE_HEADER.TimeDateStamp
str_time = time.asctime(time.gmtime(timestamp))
print "[+]Tiempo de compilacion: {} ".format(str_time)
is_packed=peutils.is_probably_packed(pe)
print "[+] Check if packed: {}".format(is_packed)

if is_packed:
    ###############################################################
    ## Debemos tener descargado las yara rules de  los packers de:#
    ## https://github.com/godaddy/yara-rules                      # 
    ###############################################################

    packer_detect(filename,"signatures/")


