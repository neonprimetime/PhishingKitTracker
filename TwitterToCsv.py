# coding: utf8
import re
import datetime
filename = "twitter.txt"
debug = 0
rawtwitterposts = ""
count = 0
urlIgnoreList = ["urlscan", "urlquery", "pastebin", "app.any.run"]
urlSaveList = ["virustotal", "github", "anonfile.com"]
emailIgnoreList = []
posts = []
postcount = 0
with open(filename, 'r') as file:
 rawtwitterposts = file.read()
 rawtwitterposts = rawtwitterposts.replace("hxxp", "http").replace("[.]", ".").replace("[.", ".").replace(".]",".").replace(" [@] ", "@").replace(" . ", ".").replace(". ", ".").replace("\.", ".")
 rawtwitterposts = rawtwitterposts.replace("[@]","@").replace(" @ ", "@").replace("[.]", ".").replace("[.", ".").replace(".]",".").replace("<","").replace(">","").replace(".com,", ".com , ").replace(",com", ".com").replace("^","").replace("(","").replace(")","").replace("\"", "").replace("'","").replace("{at}", "@").replace("symbol", " ").replace("?"," ")
 #rawtwitterposts = rawtwitterposts.replace("\r", " ").replace("\n", " ")
 
 while len(rawtwitterposts) > 0:
  try:
   # find the first dot
   indexof1stdot = rawtwitterposts.index('·')
   # get rid of the first dot
   rawtwitterposts = rawtwitterposts.replace('·', 'X', 1)
   # find the poster on the line before the dot
   indexof1stposter = rawtwitterposts[:indexof1stdot].rindex('@')
   try:
    # find the 2nd dot
    indexof2nddot = rawtwitterposts.index('·')
    # find the 2nd poster
    indexof2ndposter = rawtwitterposts[:indexof2nddot].rindex('@')
   except:
    indexof2nddot = len(rawtwitterposts) 
    indexof2ndposter = len(rawtwitterposts)
   # save off the 1st post
   currentpost = rawtwitterposts[indexof1stposter:indexof2ndposter]
   posts.append(currentpost)
   postcount = postcount + 1
  except:
   rawtwitterposts = ""
  rawtwitterposts = rawtwitterposts[indexof2ndposter:]

postcount = 0  
for post in posts:
 postcount = postcount + 1
 foundPoster = 0
 foundDate = 0
 foundUrl = 0
 foundSavedUrl = 0
 foundEmail = 0
 linecount = 0
 target = ""
 poster = ""
 date = ""
 url = ""
 savedurl = ""
 kitName = ""
 threatActor = ""
 emailList = []
 #print("%d) %s" % (postcount, post))
 lines = re.split('\n', post)
 for line in lines:
  line = line.lower()
  linecount = linecount + 1
  if linecount == 1:
   poster = line
  elif linecount == 3:
   parts = re.split(' |, |\.', line)
   if parts and ( len(parts) == 3 or len(parts) == 2):
    month = ""
    if parts[0] == "jan":
     month = "1"
    if parts[0] == "feb":
     month = "2"
    if parts[0] == "march" or parts[0] == "mar":
     month = "3"
    if parts[0] == "april" or parts[0] == "apr":
     month = "4"
    if parts[0] == "may":
     month = "5"
    if parts[0] == "jun":
     month = "6"
    if parts[0] == "jul":
     month = "7"
    if parts[0] == "aug":
     month = "8"
    if parts[0] == "sep":
     month = "9"
    if parts[0] == "oct":
     month = "10"
    if parts[0] == "nov":
     month = "11"
    if parts[0] == "dec":
     month = "12"
    day = parts[1]
    if len(parts) == 2:
     date = ("%s/%s/%s" % (month, day, datetime.datetime.now().year))
    else:
     date = ("%s/%s/%s" % (month, day, parts[2]))  
  else:
   urlSearch = re.search("((http|https)\:\/\/[^\s]+)", line)
   if urlSearch:
    urlToAnalyze = urlSearch.group().replace(",",".")
   else:
    urlSearch = re.search("[^\s\/]+\.(..|...)\/[^\s]+(\.php|\/)$", line)
    if urlSearch:
     urlToAnalyze = "http://" + urlSearch.group().replace(",",".")
    else:
     urlSearch = re.search("(\/\/[^\s]+)", line)
     if urlSearch:
      urlToAnalyze = "http:" + urlSearch.group().replace(",",".")
   if urlSearch:
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
   #find kit name
   if len(kitName) == 0:
    kitNameSearch = re.search("([^\s]+\.zip)", line)
    if kitNameSearch:
     kitName = kitNameSearch.group()
    else:
     kitNameSearch = re.search("([^\s]+\.zip)", url)
     if kitNameSearch:
      kitName = kitNameSearch.group()
   #find threat actor
   if len(threatActor) == 0:
    if "hijaiyh" in line:
     threatActor = "Hijaiyh"
    elif "16shop" in line:
     threatActor = "16shop"
    else:
     threatActorSearch = re.search("((created|coded|made)\sby\s[^\s]+)", line)
     if threatActorSearch:
      threatActor = threatActorSearch.group()
   #find target
   if len(target) == 0:
    try:
     if "@usbank" in line or "usbank" in url:
      target = "USBank"
     elif "targeting apple" in line or "#apple" in line or "@apple" in line or "#16shop" in line or "apple" in url or "icloud" in url:
      target = "Apple"
     elif "#hsbc" in line or "@hsbc" in line or "@hsbc_uk" in line or "hsbc" in url:
      target = "HSBC"
     elif "#chase" in line or "@chase" in line or "@chasesupport" in line or "chase" in url:
      target = "Chase"
     elif "#unicredit" in line or "@unicreditbg" in line or "unicredit" in url:
      target = "UniCredit"
     elif "#docusign" in line or "@docusign" in line or "docusign" in url:
      target = "Docusign"
     elif "#arubait" in line or "@arubait" in line or "arubait" in url:
      target = "Arubait"
     elif "#box" in line or "@box" in line:
      target = "Box"
     elif "#dhl" in line or "@dhl" in line or "dhl" in url:
      target = "DHL"
     elif "#fedex" in line or "@fedex" in line or "fedex" in url:
      target = "FedEx"
     elif "american express" in line or "#amex" in line or "@amex" in line or "americanexpress" in url:
      target = "AmEx"
     elif "#sharepoint" in line or "@sharepoint" in line or "sharepoint" in url:
      target = "Sharepoint"
     elif "#raiffeisen" in line or "@raiffeisen" in line or "raiffeisen" in url:
      target = "Raiffeisen"
     elif "#wetransfer" in line or "@wetransfer" in line or "wetransfer" in url:
      target = "WeTransfer"
     elif "#dropbox" in line or "@dropbox" in line or "dropbox" in url:
      target = "Dropbox"
     elif "#intesa" in line or "@intesasp_help" in line or "intesa" in url:
      target = "Intesa"
     elif "#spectrum" in line or "@spectrum" in line or "spectrum" in url:
      target = "Spectrum"
     elif "#santander" in line or "@santander_es" in line or "santander" in url:
      target = "Santander"
     elif "amazon themed" in line or "targeting #amazon" in line or "targeting @amazon" in line or "targeting amazon" in line:
      target = "Amazon"
     elif "#paypal" in line or "@paypal" in line or "@askpaypal" in line or "paypal" in url:
      target = "Paypal"
     elif "#instagram" in line or "@instagram" in line or "instagram" in url:
      target = "Instagram"
     elif "#onedrive" in line or "@onedrive" in line or "onedrive" in url:
      target = "OneDrive"
     elif "#netflix" in line or "@netflix" in line or "@netflixuk" in line or "netflix" in url:
      target = "Netflix"
     elif "#o365" in line or "#office365" in line or "@office365" in line or "@office_365" in line or "o365" in url or "office365" in url:
      target = "Office365"
     elif "#wellsfargo" in line or "@wellsfargo" in line or "wellsfargo" in url or "wells-fargo" in url or "wfargo" in url:
      target = "WellsFargo"
     elif "#barclays" in line or "@barclays" in line or "barclays" in url:
      target = "Barclays"
     elif "adobe themed" in line or "#adobe" in line or "@adobe" in line or "adobe" in url:
      target = "Adobe"
     elif "#excel" in line or "#msexcel" in line or "@msexcel" in line or "excel" in url:
      target = "MsExcel"
     elif "#outlook" in line or "@outlook" in line or "outlook" in url:
      target = "Outlook"
     elif "#googledocs" in line or "@googledocs" in line or "googledocs" in url or "gdocs" in url:
      target = "GoogleDocs"
    except:
     target = ""
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
    print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (date,savedurl,email,emailtype,"",target,domain,kitName,threatActor,"",kiturl))
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
    print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (date,savedurl,email,emailtype,"",target,domain,kitName,threatActor,"",kiturl))
