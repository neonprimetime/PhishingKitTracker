from urllib.request import urlopen
from urllib.request import urlretrieve
import re
import sys
import os
quietmode = 1
printstatus = 1
searchcount = 0
filepath = 'urls.txt'
with open(filepath) as fp:
 theurl = fp.readline()
 while theurl:
  searchcount = searchcount + 1
  if printstatus == 1:
   if searchcount % 10 == 0:
    print("STATUS: %s" % str(searchcount))
  if(not theurl.startswith('http')):
   if(":443" in theurl):
    theurl = 'https://' + theurl.strip()
   else:
    theurl = 'http://' + theurl.strip()
  theurl = theurl.strip()
  if(theurl.endswith("/") or theurl.endswith("\\")):
   theurl = theurl[:-1]
  stopnow = 0
  while stopnow == 0:
   try:
    domain = theurl.split("//")[-1].split("/")[0]
    currentfolder = theurl.split("/")[-1]
    html = urlopen(theurl, timeout=3)
    val = html.read()
    titles = re.findall(r'(?i)<title>(.*?)</title>',str(val))
    if len(titles) > 0:
     if titles[0].startswith('Index of'):
      print("-OPENDIR-," + titles[0] + "," + theurl)
      zipfiles = re.findall(r'(?i)href\=\"[^\"]+\.php\"\>',str(val))
      if len(zipfiles) > 0:
       for zipfile in zipfiles:
        zipfile = zipfile.replace('\"', '').replace('href=', '').replace('>','').replace("&amp;", "&")
        if theurl.endswith('/'):
         phishkit = theurl + zipfile
        else:
         phishkit = theurl + "/" + zipfile
        print("**FILE**," + phishkit)
      zipfiles = re.findall(r'(?i)href\=\"[^\"]+\.txt\"\>',str(val))
      if len(zipfiles) > 0:
       for zipfile in zipfiles:
        zipfile = zipfile.replace('\"', '').replace('href=', '').replace('>','').replace("&amp;", "&")
        if theurl.endswith('/'):
         phishkit = theurl + zipfile
        else:
         phishkit = theurl + "/" + zipfile
        print("**FILE**," + phishkit)
      zipfiles = re.findall(r'(?i)href\=\"[^\"]+\.zip\"\>',str(val))
      if len(zipfiles) > 0:
       for zipfile in zipfiles:
        zipfile = zipfile.replace('\"', '').replace('href=', '').replace('>','').replace("&amp;", "&")
        if theurl.endswith('/'):
         phishkit = theurl + zipfile
        else:
         phishkit = theurl + "/" + zipfile
        print("**FILE**," + phishkit)
      zipfiles = re.findall(r'(?i)href\=\"[^\"]+\.log\"\>',str(val))
      if len(zipfiles) > 0:
       for zipfile in zipfiles:
        zipfile = zipfile.replace('\"', '').replace('href=', '').replace('>','').replace("&amp;", "&")
        if theurl.endswith('/'):
         phishkit = theurl + zipfile
        else:
         phishkit = theurl + "/" + zipfile
        print("**FILE**," + phishkit)
     else:
      print("-PAGE-," + titles[0] + "," + theurl)
    theurl = re.sub(r'\/[^\/]*$', '', theurl)
    if theurl.endswith('http:/') or theurl.endswith('https:/'):
     stopnow = 1
   except Exception as e:
    if "no host given" in str(e):
     stopnow = 1
    else:
     if quietmode == 0:
      print("-FAILED-," + str(e) + "," + theurl)
     theurl = re.sub(r'\/[^\/]*$', '', theurl)
  theurl = fp.readline()
