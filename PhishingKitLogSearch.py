import requests
import os
filepath = 'urls.txt'
folders = ["", "log", "logs", "script", "scripts"]
files = ["logs.txt", "log.txt", "log.html", "logs.html", "error_logs.txt", "error_log.txt", "script.txt", "1.php", "ise.txt", "user.txt", "users.txt", "stored.txt", "fullz.txt", "accounts.txt", "login.txt", "logins.txt", "U1.txt", "results.txt", "resultz.txt"]
printfailures = 0
foundcount = 0
quietmode = 1
printstatus = 1
searchcount = 0
with open(filepath) as fp:
 theurl = fp.readline()
 while theurl:
  searchcount = searchcount + 1
  theurl = theurl.strip()
  lastparen = theurl.rfind("/")
  baseurl = ""
  if lastparen > 10:
   baseurl = theurl[:lastparen]
  else:
   baseurl = theurl
  if printstatus == 1:
   if searchcount % 10 == 0:
    print("----------")
    print("STATUS   : %s done" % searchcount)
    print("----------")
  if quietmode == 0:
   print("----------")
   print("TESTING  : %s" % baseurl)
   print("----------")
  timeout = 0
  foundcount = 0
  for folder in folders:
   if timeout == 1:
    break
   if foundcount > 2:
    break
   for file in files:
    if timeout == 1:
     if quietmode == 0:
      print("**TIMEOUT DETECTED, CANCELLING")
     break
    if foundcount > 2:
     print("**HIGH HIT RATE DETECTED, STOPPING SEARCH, LIKELY FALSE POSITIVE")
     break
    stem = ("/%s/%s" % (folder, file))
    stem = stem.replace("//", "/")
    url = ("%s%s" % (baseurl, stem))
    try:
     response = requests.get(url, timeout=2)
     if response.status_code == 200:
      foundcount = foundcount + 1
      if quietmode == 1:
       if foundcount == 1:
        print("----------")
        print("URL      : %s" % baseurl)
        print("----------")
      print("=>FOUND<=: %s (RESPONSE: %s)" % ( stem , str(response.status_code) ))
     else:
      if printfailures == 1:
       if quietmode == 0:
        print("**FAIL   : %s (RESPONSE: %s)" % ( stem , str(response.status_code) ))
    except:
     timeout = 1
     if printfailures == 1:
      if quietmode == 0:
       print("**FAIL   : %s (TIMEOUT)" % theurl)
  if foundcount == 0:
   if quietmode == 0:
    print("**0 HITS")
  theurl = fp.readline()
