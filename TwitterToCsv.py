# coding: utf8
import re
filename = "twitter.txt"
debug = 0
rawtwitterposts = ""
count = 0
urlIgnoreList = ["urlscan", "urlquery", "pastebin", "app.any.run"]
urlSaveList = ["virustotal", "github"]
emailIgnoreList = []
with open(filename, 'r') as file:
 rawtwitterposts = file.read()
 rawtwitterposts = re.sub(r'([@][^\n]+)\n.*·', r'·\1', rawtwitterposts).replace("@PhishKitTracker", "").replace("@Spam404Online","").replace("@google","").replace("#phishingkit","").replace("#phishing","").replace("Osumi, Yusuke", "").replace("International Phish Actors Expose!", "").replace("Beeker Five one", "").replace("phisher;", "").replace("sample;", "")
 rawtwitterposts = rawtwitterposts.replace("hxxp", "http").replace("[.]", ".").replace("[.", ".").replace(".]",".").replace(" [@] ", "@").replace(" . ", ".").replace(". ", ".").replace("\.", ".")
 rawtwitterposts = rawtwitterposts.replace("[@]","@").replace(" @ ", "@").replace("[.]", ".").replace("[.", ".").replace(".]",".").replace("<","").replace(">","").replace(".com,", ".com , ").replace(",com", ".com")
 rawposts = re.split('·', rawtwitterposts)
 # START: RAW POST ANALYSIS
 for rawpost in rawposts:
  count = count + 1
  lines = re.split('\n', rawpost)
  linecount = 0
  foundPoster = 0
  foundDate = 0
  foundUrl = 0
  foundSavedUrl = 0
  foundEmail = 0
  poster = ""
  date = ""
  url = ""
  savedurl = ""
  emailList = []
  # START: LINE PARSING
  for line in lines:
   linecount = linecount + 1
   if foundPoster == 0:
    if line.startswith("@"):
     poster = line
     foundPoster = 1
   if foundDate == 0:
    if line.startswith("Jan ") or line.startswith("Feb ") or line.startswith("March ") or line.startswith("April ") or line.startswith("May ") or line.startswith("Jun ") or line.startswith("July ") or line.startswith("Aug ") or line.startswith("Sep ") or line.startswith("Oct ") or line.startswith("Nov ") or line.startswith("Dec "):
     parts = re.split(' |, |\.', line)
     if parts and len(parts) == 3:
      month = ""
      if parts[0] == "Jan":
       month = "1"
      if parts[0] == "Feb":
       month = "2"
      if parts[0] == "March":
       month = "3"
      if parts[0] == "April":
       month = "4"
      if parts[0] == "May":
       month = "5"
      if parts[0] == "Jun":
       month = "6"
      if parts[0] == "July":
       month = "7"
      if parts[0] == "Aug":
       month = "8"
      if parts[0] == "Sep":
       month = "9"
      if parts[0] == "Oct":
       month = "10"
      if parts[0] == "Nov":
       month = "11"
      if parts[0] == "Dec":
       month = "12"
      day = parts[1]
      date = ("%s/%s/%s" % (month, day, parts[2]))
      foundDate = 1
   urlSearch = re.search("((http|https)\:\/\/[^\s]+)", line)
   if urlSearch:
    urlToAnalyze = urlSearch.group().replace(",",".")
    thisIsSavedUrl = 0
    if foundSavedUrl == 0:
     for urlToSave in urlSaveList:
      if urlToSave in urlToAnalyze:
       savedurl = urlToAnalyze
       foundSavedUrl = 1
       thisIsSavedUrl = 1
       break
    if foundUrl == 0 and thisIsSavedUrl == 0:
     for urlToIgnore in urlIgnoreList:
      if urlToIgnore in urlToAnalyze:
       urlToAnalyze = ""
       break
     if len(urlToAnalyze) > 7 and thisIsSavedUrl == 0:
      url = urlToAnalyze
      foundUrl = 1
   emailline = line
   while len(emailline) > 0:
    emailSearch = re.search("([^\s\,\;]+([@]|\s[@]\s)[^\s\,\;]+)", emailline)
    if emailSearch:
     emailToAnalyze = emailSearch.group()
     emailline = emailline[emailline.index(emailToAnalyze) + len(emailToAnalyze):]
     if not ("http://" in emailToAnalyze or "https://" in emailToAnalyze or "=" in "http://" or "?" in emailToAnalyze):
      if emailToAnalyze[len(emailToAnalyze)-1:] == ",":
       emailToAnalyze = emailToAnalyze[0:len(emailToAnalyze)-1]
      emailToAnalyze = emailToAnalyze.replace(",",".")
      if len(emailToAnalyze) > 0:
       for emailToIgnore in emailIgnoreList:
        if emailToIgnore in emailToAnalyze:
         emailToAnalyze = ""
         break
      else:
       emailline = ""
      if len(emailToAnalyze) > 0:
       emailList.append(emailToAnalyze)
       foundEmail = 1
      else:
       emailline = ""
     else:
      emailline = ""
    else:
     emailline = ""
  # START: DISPLAY RESULTS
  if foundEmail or foundSavedUrl:
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
    if len(email) > 7 and len(savedurl) == 0 and len(poster) > 3:
     savedurl = ("https://twitter.com/%s/" % (poster.replace("@","")))
    # DateFound,ReferenceLink,ThreatActorEmail,EmailType,KitMailer,Target,PhishingDomain,KitName,ThreatActor,KitHash,KitUrl
    if(len(email) > 7 or len(savedurl) > 7):
     print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (date,savedurl,email,emailtype,"","",domain,"","","",kiturl))
   if emailCount == 0 and foundSavedUrl == 1:
    email = ""
    emailtype = ""
    kiturl = ""
    domain = ""
    if ".zip" in url:
     kiturl = url
    else:
     parts = url.split("/")
     if len(parts) > 2:
      domain = parts[2]
    if len(email) > 7 and len(savedurl) == 0 and len(poster) > 3:
     savedurl = ("https://twitter.com/%s/" % (poster.replace("@","")))
    # DateFound,ReferenceLink,ThreatActorEmail,EmailType,KitMailer,Target,PhishingDomain,KitName,ThreatActor,KitHash,KitUrl
    if(len(email) > 7 or len(savedurl) > 7):
     print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (date,savedurl,email,emailtype,"","",domain,"","","",kiturl))
