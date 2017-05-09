### Archivo con funciones auxiliares

import os 
import glob
import sys
import json
import requests
import yara
import collections
import hashlib
import pefile

suspicious_imports = ['LoadLibraryA','LoadLibraryEx','LoadLibraryEx','SetThreadPriority','GetSystemInfo','GetProcAddress','FreeLibrary', 'InternetConnectA', 'HttpSendRequestA', 'InternetReadFile', 'ShellExecuteA', 'ShellExecuteExA']

def getAvSignature(filename):
    hash = md5(filename)
    params = {'apikey': '73dec1b2f94c85bacaf5dead7626b9e3f0f0e03972df3f10bf71a1a71d2bdd01', 'resource': hash}
    headers = {
          "Accept-Encoding": "gzip, deflate",
          "User-Agent" : "gzip,  Practica 2 Analisis malware"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
    params=params, headers=headers)
    json_response = response.json()
    #print json.dumps(json_response, indent=4, sort_keys=True)
    signatures=[]
    if json_response["response_code"] == 0: 
        print "[!] File not scanned" 
        return collections.Counter(signatures)
    
    for av,value in json_response["scans"].iteritems():
         signatures.append(value["result"])
      
    counter=collections.Counter(signatures)
    return counter
    
    
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def md5_bin(data):
    hash_md5 = hashlib.md5()
    hash_md5.update(data)
    return hash_md5.hexdigest()


    
def packer_detect(pe_file,path_rules):
    current_cwd = os.getcwd()
    os.chdir( path_rules )
    packer = None
    for file in list(glob.glob('*.yara')):
        print "[I] Testing  signature '{}' ".format(file)
        try:
            rules = yara.compile(file) 
        except yara.SyntaxError:
            print "[!] Cannot process yara signature: {}".format(file)
        yara_matches = rules.match(current_cwd + "/" + pe_file)
        if yara_matches:
            print "[+] Packer detected {}".format(yara_matches[0])
            packer = yara_matches[0]
    os.chdir(current_cwd)
    return packer
    
def get_dll(pe):
    """ Extract the imported DLL files from the PE file """
    # If the PE has the attribute, create a list with DLL's
    if pe != False and hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        dll_list = [i.dll for i in pe.DIRECTORY_ENTRY_IMPORT]
        return sorted(set(dll_list))
    return None

def get_strings(pe):
    # The List will contain all the extracted Unicode strings
    #
    strings = list()

    # Fetch the index of the resource directory entry containing the strings
    #
    rt_string_idx = [
      entry.id for entry in 
      pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_STRING'])

    # Get the directory entry
    #
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

    # For each of the entries (which will each contain a block of 16 strings)
    #
    for entry in rt_string_directory.directory.entries:

      # Get the RVA of the string data and
      # size of the string data
      #
      data_rva = entry.directory.entries[0].data.struct.OffsetToData
      size = entry.directory.entries[0].data.struct.Size
      print 'Directory entry at RVA', hex(data_rva), 'of size', hex(size)

      # Retrieve the actual data and start processing the strings
      #
      data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
      offset = 0
      while True:
        # Exit once there's no more data to read
        if offset>=size:
          break
        # Fetch the length of the unicode string
        #
        ustr_length = pe.get_word_from_data(data[offset:offset+2], 0)
        offset += 2

        # If the string is empty, skip it
        if ustr_length==0:
          continue

        # Get the Unicode string
        #
        ustr = pe.get_string_u_at_rva(data_rva+offset, max_length=ustr_length)
        offset += ustr_length*2
        strings.append(ustr)
        print 'String of length', ustr_length, 'at offset', offset
    return strings
    
def get_resources(pe):

    # Fetch the index of the resource directory entry containing the strings
    #
    rt_resource_idx = [
      entry.id for entry in 
      pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_BITMAP'])

    
    rt_resource_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_resource_idx]

    
    for entry in rt_resource_directory.directory.entries:
      print entry.directory.entries[0].data.struct
      data_rva = entry.directory.entries[0].data.struct.OffsetToData
      size = entry.directory.entries[0].data.struct.Size
      print 'Directory entry at RVA', hex(data_rva), 'of size', hex(size)
      
      #data = pe.get_memory_mapped_image()[data_rva : data_rva+size]
      data=pe.get_data(data_rva,size)
      
      print bytearray(data)
      with open(md5_bin(data)+'.bmp', 'wb') as bmp:
        bmp.write(bytearray(data))
      print 'Print BMP found'
      
"""
extracts the first 18 bytes of the icon header from RT_GROUP_ICON data, 
appends with a dword value 22 to signify the offset
and then appends the raw icon data from RT_ICON
"""
def extract_icon(pe):
    """
    pe is a pefile object
    """
    rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_GROUP_ICON'])
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
    rt_string_directory = [e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == pefile.RESOURCE_TYPE['RT_GROUP_ICON']][0]
   
    
    entry = rt_string_directory.directory.entries[-1] # gives the highest res icon
    offset = entry.directory.entries[0].data.struct.OffsetToData
    size = entry.directory.entries[0].data.struct.Size
    data = pe.get_memory_mapped_image()[offset:offset+size]
    icon = data[:18]+'\x16\x00\x00\x00'

    rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_ICON'])
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
    rt_string_directory = [e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == pefile.RESOURCE_TYPE['RT_ICON']][0]
    entry = rt_string_directory.directory.entries[-1] # gives the highest res icon
    offset = entry.directory.entries[0].data.struct.OffsetToData
    size = entry.directory.entries[0].data.struct.Size
    icon += pe.get_memory_mapped_image()[offset:offset+size]
    with open(md5_bin(icon)+'.ico', 'wb') as ico:
        ico.write(bytearray(icon))
