import re
from datetime import date
import argparse

arguments = argparse.ArgumentParser("Extract Urls from a phishing site like PhishTank")
arguments.add_argument("-f", "--file", type=str, required=True, help="Path to file with raw copy & paste content of website")
settings = arguments.parse_args()

urlregex = r'(?i)(http|https|hxxp|hxxps)(\:\/\/[^\s]+)\s'

splitchoice1 = "http"
splitchoice2 = "hxxp"

filename = settings.file
webpageraw = ''
with open(filename, 'r') as file:
 webpageraw = file.read()

splitter = splitchoice1
urlchunks = []
try:
 end = webpageraw.index(splitter)
except:
 splitter = splitchoice2
 try:
  end = webpageraw.index(splitter)
 except:
  end = -1
if end < 0:
 urlchunks.append(webpageraw)
else:
 while end >= 0:
  urlchunks.append(splitter + webpageraw[:end])
  newstart = end + len(splitter)
  webpageraw = webpageraw[newstart:]
  try:
   end = webpageraw.index(splitter)
  except:
   end = -1
 urlchunks.append(splitter + webpageraw)
for urlchunk in urlchunks:
 searchurl = re.search(urlregex,urlchunk)
 url = ''
 if not searchurl is None:
  url = searchurl[1] + searchurl[2]
  if not url is None:
   print("{0}".format(url).replace("...",""))
