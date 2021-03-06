import time
import sys
import os
import pefile
import peutils
import pexutils
import subprocess

pe_filename = sys.argv[1]
sigs = pexutils.getAvSignature(pe_filename)
print "[+] Av. Signatures"
print " | {:<40} | {:<5} |".format('Signature','Count')
for count, row in sorted(sigs.iteritems(), key=lambda x:x[1]):  #sigs.iteritems():
    print " | {:<40} | {:<5} |".format(count, row)


pe = pefile.PE(pe_filename)
timestamp = pe.FILE_HEADER.TimeDateStamp
str_time = time.asctime(time.gmtime(timestamp))
print "[+] Build timestamp: {} ".format(str_time)
is_packed=peutils.is_probably_packed(pe)
print "[+] Check if packed: {}".format(is_packed)

if is_packed:
    ###############################################################
    ## Debemos tener descargado las yara rules de  los packers de:#
    ## https://github.com/godaddy/yara-rules                      # 
    ###############################################################
    packer = pexutils.packer_detect(pe_filename, os.path.dirname(os.path.realpath(__file__)) + "/signatures/packers/")
    if str(packer) == "upx":
        print "[I] Trying to decompile UPX file"
        unpacked_filename = pe_filename+ ".unpacked"
        if os.path.exists(unpacked_filename):
            os.remove(unpacked_filename)
        DEVNULL = open(os.devnull, 'wb')
        subprocess.check_call(["upx", "-d",pe_filename,"-o",unpacked_filename],stdout=DEVNULL)
        print "[!] Created file {}".format(unpacked_filename)
        pe_filename = unpacked_filename
    else:
        print "[I] I don't know how to unpack this"
        
# Recargamos el archivo por si estuviera empaquetado
pe.close()
pe = pefile.PE(pe_filename)
print "[+] Libraries"
for lib in  pexutils.get_dll(pe):  #sigs.iteritems():
    print " {} ".format(lib)
print "[+] Exporting import table to: importtable.txt"
with open('importtable.txt', 'w') as impf:
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        impf.write(entry.dll + "\n")
        for imp in entry.imports:
            if imp.name in pexutils.suspicious_imports: print "[!] Suspicious import: {}".format(imp.name)
            impf.write('\t {:<10} {} \n'.format(hex(imp.address), imp.name))
        
#print pexutils.get_strings(pe)
#pexutils.get_resources(pe)
pexutils.extract_icon(pe)

pe.close()