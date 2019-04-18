# phishing kit parser, used to enrich kit and put into PhishingKitTracker csv format
# @neonprimetime
# https://github.com/neonprimetime/PhishingKitTracker/
import argparse
import zipfile
import urllib.request
from urllib.parse import urlparse
import os
from pathlib import Path
import re
from datetime import date
import hashlib
import shutil

#definitions
class PhishingKitTrackerEntry:
 date = date.today().strftime('%m/%d/%Y')
 reference = ""
 email = ""
 emailProvider = ""
 mailer = ""
 target = ""
 domain = ""
 zip = ""
 threatActor = ""
 md5 = ""
 url = ""
entries = []
proceed = 1
domain = ""
mailer = ""
filename = ""
md5 = ""
threatActor = ""
itemList = []
isUrls = 0
extractedfoldername = ""

#arguments
arguments = argparse.ArgumentParser("Analyze Phishing Kit, pass 1 url or file to start")
arguments.add_argument("-u", "--url", type=str, required=False, help="Url to a Phishing Kit Zip file") 
arguments.add_argument("-f", "--file", type=str, required=False, help="Path to a Phishing Kit Zip file") 
arguments.add_argument("-d", "--debug", action="store_true", required=False, help="Enable debugging messages")
arguments.add_argument("-r", "--reference", type=str, required=False, help="Twitter url referencing Phishing Kit")
arguments.add_argument("-l", "--listUrls", type=str, required=False, help="Path to file with a list of Urls to Phishing Kit Zip files in it 1 per line")
arguments.add_argument("-i", "--listFiles", type=str, required=False, help="Path to file with a list of Phishing Kit Zip files 1 per line")
settings = arguments.parse_args()
if(settings.url is None):
 if(settings.file is None):
  if(settings.listUrls is None):
   if(settings.listFiles is None):
    if(settings.debug):
     print("no url, file, or list param found")
    proceed = 0
    raise Exception("url (-u) or file (-f) or list (-l,-i) required")
   else:
    if(settings.debug):
     print("list of files param found '{0}'".format(settings.listFiles))
    with open(settings.listFiles) as f:
     for line in f:
      itemList.append(line.rstrip("\r\n"))
  else:
   if(settings.debug):
    print("list of urls param found '{0}'".format(settings.listUrls))
   with open(settings.listUrls) as f:
    for line in f:
     itemList.append(line.rstrip("\r\n"))
   isUrls = 1
 else:
  if(settings.debug):
   print("file param found'{0}'".format(settings.file))
  itemList.append(settings.file)
else:
 if(settings.debug):
  print("url param found '{0}'".format(settings.url))
 itemList.append(settings.url)
 isUrls = 1

#processing
if(proceed == 1):
 for item in itemList:
  if(isUrls == 0):
   filename = item
  else:
   try:
    url = urlparse(item)
    domain = url.netloc
    filename = os.path.basename(url.path)
    if(settings.debug):
     print("found domain '{0}'".format(domain))
     print("found filename '{0}'".format(filename))
    urllib.request.urlretrieve(item, filename)
    if(settings.debug):
     print("url downloaded '{0}'".format(item))
   except:
    print("failed to download '{0}'".format(item))
    continue
  try:
   extractedfoldername = str(Path(filename).with_suffix(""))
  except:
   print("failed to build folder name '{0}'",format(item))
  if(settings.debug):
   print("getting file hash for '{0}'".format(filename))
  try:
   file = open(filename, 'rb')
   with file:
    md5 = hashlib.md5(file.read()).hexdigest()
  except:
   print("unable to open file '{0}'".format(filename))
  if(settings.debug):
   print("unzipping file '{0}' to '{1}'".format(filename,extractedfoldername))
  try:
   with zipfile.ZipFile(filename,'r') as zip_ref:
    zip_ref.extractall(extractedfoldername)
  except:
   print("failed to unzip '{0}'".format(filename))
  if(settings.debug):
   print("file unzipped to '{0}'".format(extractedfoldername))
  if(settings.debug):
   print("starting search for Threat Actor Signatures")
  foundActor = 0
  threatActor = ""
  for dname, dirs, files in os.walk(extractedfoldername):
   if(foundActor == 0):
    for fname in files:
     fpath = os.path.join(dname, fname)
     extension = os.path.splitext(fpath)[1]
     if(settings.debug):
      print("found file '{0}' with extension '{1}'".format(fpath,extension))
     if(extension is not None and extension == ".php"):
      if(settings.debug):
       print("searching file '{0}'".format(fpath))
      with open(fpath) as f:
       try:
        line = f.read()
        match = re.search(r'(?i)(created by|hacked by|coded by|edited by|signed by|made by)([^\r\n\=\+\"\'\,]+)\s+([\,\=\+\"\']|\-\-)', line)
        if(match is not None):
         threatActor = match.group(1) + match.group(2)
         foundActor = 1
         break
       except:
        print("failed to open '{0}'".format(fpath))
  if(settings.debug):
   print("finished search for Threat Actor Signatures")
  if(settings.debug):
   print("starting search for Threat Actor Emails")
  for dname, dirs, files in os.walk(extractedfoldername):
   for fname in files:
    fpath = os.path.join(dname, fname)
    mailer = os.path.basename(fpath)
    extension = os.path.splitext(fpath)[1]
    if(settings.debug):
     print("found file '{0}' with extension '{1}'".format(fpath,extension))
    if(extension is not None and extension == ".php"):
     if(settings.debug):
      print("searching file '{0}'".format(fpath))
     with open(fpath) as f:
      try:
       line = f.read()
       matches = re.findall(r'[\w\.-]+@[\w\.-]+', line)
       for match in matches:
        if(settings.debug):
         print("found threat actor email '{0}'".format(match))
        entry = PhishingKitTrackerEntry()
        if(settings.reference is not None):
         entry.reference = settings.reference
        entry.email = match
        entry.emailProvider = match.split('@')[1].split('.')[0]
        entry.mailer = mailer
        entry.domain = domain
        entry.zip = filename
        entry.threatActor = threatActor
        entry.md5 = md5
        if(isUrls == 1):
         entry.url = item
        entries.append(entry)
      except:
       print("failed to open '{0}'".format(fpath))
  if(settings.debug):
   print("deleting zip '{0}'".format(filename))
  if(filename is not None and filename != "" and ".zip" in filename):
   os.remove(filename)
  if(settings.debug):
   print("deleting folder '{0}'".format(extractedfoldername))
  if(extractedfoldername is not None and extractedfoldername != ""):
   shutil.rmtree(extractedfoldername, ignore_errors=True)
  if(settings.debug):
   print("finished search for Threat Actor Emails")
else:
 if(settings.debug):
  print("exiting program, proceed={0}".format(str(proceed)))


#output
for entry in entries:
 print("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}".format(entry.date,entry.reference,entry.email,entry.emailProvider,entry.mailer,entry.target,entry.domain,entry.zip,entry.threatActor,entry.md5,entry.url))
