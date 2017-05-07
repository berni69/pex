### Archivo con funciones auxiliares

import os 
import glob
import sys
import json
import requests
import yara
import collections
import hashlib

    
    
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
    print json.dumps(json_response, indent=4, sort_keys=True)
    signatures=[]
    if json_response["response_code"] == 0: 
        print "[!] File not scanned" 
        return signatures
    
    for av,value in json_response["scans"].iteritems():
         signatures.append(value["result"])
      
    counter=collections.Counter(a)
    print(counter)   
    return signatures
    
    
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()
        
def packer_detect(file,path_rules):
    for file in list(glob.glob('*.yara')):      
        rules = yara.compile(args.yara) 
        yara_matches = rules.match(file)
        try:
            for yara_match in yara_matches['main']:
                try:
                    print('Yara: ' + yara_match['meta']['description'])
                except KeyError:
                    pass
        except KeyError:
            pass
            
            
def get_dll(pe):
    """ Extract the imported DLL files from the PE file """
    # If the PE has the attribute, create a list with DLL's
    if pe != False and hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        dll_list = [i.dll for i in pe.DIRECTORY_ENTRY_IMPORT]
        return ','.join(dll_list)
    return None