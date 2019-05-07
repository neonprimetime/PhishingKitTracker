import re
from datetime import date
import argparse

arguments = argparse.ArgumentParser("Format Twitter Post for Phishing KitTracker")
arguments.add_argument("-f", "--file", type=str, required=True, help="Path to file with twitter post")
arguments.add_argument("-c", "--comments", action="store_true", required=False, help="Output individual twitter replies too")
settings = arguments.parse_args()

emailregex = r'(?i)(\s|\"|\'|\,|\,\s+)([^\@\s\"]+\@[^\s\"]+)(\[\.\].{2,3}|\.[^\]].{1,2})(\"|\'|\s|\,)'
domainregex = r'(?i)(hxxp|http|https|hxxps)\:\/\/([^\/\s]+)(\/|\s)'
emaildomainregex = r'(?i)[\@]([^\.]+)\.'
emailkeepregex = r'(?i)(gmail|yahoo|zoho|yandex|aol|mail\.ru|outlook|hotmail|protonmail|live\.com|mail\.com)'

splitchoice1 = "@neonprimetime"
splitchoice2 = "Phisher"

filename = settings.file
twitterpostsraw = ''
with open(filename, 'r') as file:
 twitterpostsraw = file.read()

splitter = splitchoice1
twitterposts = []
try:
 end = twitterpostsraw.index(splitter)
except:
 splitter = splitchoice2
 try:
  end = twitterpostsraw.index(splitter)
 except:
  end = -1
if end < 0:
 twitterposts.append(twitterpostsraw)
else:
 while end >= 0:
  twitterposts.append(twitterpostsraw[:end])
  newstart = end + len(splitter)
  twitterpostsraw = twitterpostsraw[newstart:]
  try:
   end = twitterpostsraw.index(splitter)
  except:
   end = -1
 twitterposts.append(twitterpostsraw)

date = date.today().strftime('%-m/%-d/%Y')

for twitterpost in twitterposts:
 searchdomain = re.search(domainregex,twitterpost)
 domain = ''
 if not searchdomain is None:
  domain = searchdomain[2].replace("[.]",".")
 searchemail = re.search(emailregex,twitterpost)
 while not searchemail is None:
  originalemail = (searchemail[2] + searchemail[3])
  email = originalemail.replace("[.]",".")
  searchemaildomain = re.search(emaildomainregex,email)
  if not searchemaildomain is None:
   emaildomain = searchemaildomain[1]
  if email:
   searchemailkeep = re.search(emailkeepregex,email)
   if not searchemailkeep is None:
    print("{0},,{1},{2},,,{3},,,,".format(date,email,emaildomain,domain))
    if(settings.comments):
     print("\r\nAdded #threatactoremail to PhishingKitTracker\r\n\r\n{0}".format(email.replace("@"," @ ").replace(".", "[.]")))
  emailindex = twitterpost.index(originalemail)
  newstart = emailindex + len(originalemail) - 1
  twitterpost = twitterpost[newstart:]
  searchemail = re.search(emailregex,twitterpost)
