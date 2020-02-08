# coding: utf8
import re
filename = "twitter.txt"
debug = 0
rawtwitterposts = ""
count = 0
urlIgnoreList = ["urlscan", "urlquery", "pastebin", "app.any.run"]
urlSaveList = ["virustotal", "github"]
emailIgnoreList = []
poster = ""
date = ""
url = ""
emailList = []
with open(filename, 'r') as file:
 rawtwitterposts = file.read()
 rawposts = re.split('·', rawtwitterposts)
 for rawpost in rawposts:
  if debug and len(emailList) > 0:
   print("DEBUG: poster=%s" % poster)
   print("DEBUG:  date=%s" % date)
   print("DEBUG:  url=%s" % url)
   print("DEBUG:  savedurl=%s" % savedurl)
  emailCount = 0
  for email in emailList:
   emailCount = emailCount +1
   parts1 = email.split("@")
   emailtype = ""
   if len(parts1) == 2:
    parts2 = parts1[1].split(".")
    if len(parts2) > 1:
     emailtype = parts2[0]
   kiturl = ""
   domain = ""
   if ".zip" in url:
    kiturl = url
   else:
    parts = url.split("/")
    if len(parts) > 2:
     domain = parts[2]
   if len(savedurl) == 0:
    savedurl = ("https://twitter.com/%s/" % (poster.replace("@","")))
   # DateFound,ReferenceLink,ThreatActorEmail,EmailType,KitMailer,Target,PhishingDomain,KitName,ThreatActor,KitHash,KitUrl
   print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (date,savedurl,email,emailtype,"","",domain,"","","",kiturl))
   if debug:
    print("DEBUG:  email%s=%s" % (str(emailCount), email))
  count = count + 1
  date = ""
  url = ""
  savedurl = ""
  emailList = []
  if count == 1:
   lines = re.split('\n', rawpost)
   # grab "first" poster
   for line in lines:
    if line.startswith("@"):
     poster = line
  else:
   lines = re.split('\n', rawpost)
   # grab "next" poster & extract previous post
   for line in lines:
    if line.startswith("Jan ") or line.startswith("Feb ") or line.startswith("March ") or line.startswith("April ") or line.startswith("May ") or line.startswith("June ") or line.startswith("July ") or line.startswith("Aug ") or line.startswith("Sep ") or line.startswith("Oct ") or line.startswith("Nov ") or line.startswith("Dec "):
     parts = re.split(' |, ', line)
     if parts and len(parts) == 3:
      month = ""
      if parts[0] == "Jan":
       month = "01"
      if parts[0] == "Feb":
       month = "02"
      if parts[0] == "March":
       month = "03"
      if parts[0] == "April":
       month = "04"
      if parts[0] == "May":
       month = "05"
      if parts[0] == "June":
       month = "06"
      if parts[0] == "July":
       month = "07"
      if parts[0] == "Aug":
       month = "08"
      if parts[0] == "Sep":
       month = "09"
      if parts[0] == "Oct":
       month = "10"
      if parts[0] == "Nov":
       month = "11"
      if parts[0] == "Dec":
       month = "12"
      day = parts[1]
      if len(day) == 1:
       day = ("0%s" % day)
      date = ("%s/%s/%s" % (month, day, parts[2]))
    if len(url) == 0:
     urlSearch = re.search("((http|hxxp|https|hxxps)\:\/\/[^\s]+)", line)
     if urlSearch:
      url = urlSearch.group().replace("hxxp", "http").replace("[.]", ".").replace("[.", ".").replace(".]",".").replace(",",".")
      if len(url) > 0:
       for urlToSave in urlSaveList:
        if urlToSave in url:
         savedurl = url
         url = ""
         if debug:
          print("DEBUG: Found Save url %s" % savedurl)
         break
       if len(url) > 0:
        for urlToIgnore in urlIgnoreList:
         if urlToIgnore in url:
          if debug:
           print("DEBUG: Ignoring url %s" % url)
          url = ""
          break
        if debug:
         print("DEBUG: Found url %s" % url)
    emailSearch = re.search("([^\s]+([@]|\s[@]\s)[^\s]+)", line)
    if emailSearch:
     email = emailSearch.group().replace("[@]","@").replace(" @ ", "@").replace("[.]", ".").replace("[.", ".").replace(".]",".").replace(",",".")
     if len(email) > 0:
      for emailToIgnore in emailIgnoreList:
       if emailToIgnore in email:
        if debug:
         print("DEBUG: Ignoring email %s" % email)
        email = ""
        break
     if len(email) > 0:
      emailList.append(email)
    if line.startswith("@"):
     poster = line
if debug and len(emailList) > 0:
 print("DEBUG: poster=%s" % poster)
 print("DEBUG:  date=%s" % date)
 print("DEBUG:  url=%s" % url)
 print("DEBUG:  savedurl=%s" % savedurl)
emailCount = 0
for email in emailList:
 emailCount = emailCount +1
 parts1 = email.split("@")
 emailtype = ""
 if len(parts1) == 2:
  parts2 = parts1[1].split(".")
  if len(parts2) > 1:
   emailtype = parts2[0]
 kiturl = ""
 domain = ""
 if ".zip" in url:
  kiturl = url
 else:
  parts = url.split("/")
  if len(parts) > 2:
   domain = parts[2]
 if len(savedurl) == 0:
  savedurl = ("https://twitter.com/%s/" % (poster.replace("@","")))
 # DateFound,ReferenceLink,ThreatActorEmail,EmailType,KitMailer,Target,PhishingDomain,KitName,ThreatActor,KitHash,KitUrl
 print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (date,savedurl,email,emailtype,"","",domain,"","","",kiturl))
 if debug:
  print("DEBUG:  email%s=%s" % (str(emailCount), email))
