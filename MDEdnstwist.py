import os
import csv
import dnstwist #pip install this
import datetime
from pathlib import Path

whitelist =["example.com"]
domainlist = []
reason =[]
print("Tool Written by Jkerai1 https://github.com/jkerai1\n")
query = input("Domain to twist? ")
if query == "":
    query = "microsoft.com" #FallBack

IOC_Columns = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"]
stamp = datetime.datetime.now().strftime("%x").replace("/","-")
filename = "DNSTwist " + query + stamp + ".csv"

if os.path.exists(filename)== False:
    with open(filename, 'a+',newline='') as file:
        writer = csv.writer(file)
        writer.writerow(IOC_Columns)

z = dnstwist.run(domain=query, format = 'csv') #,tld = 'common_tlds.dict') if you need extra TLDs.  OR ,dictionary = 'english.dict') if you need a wider dictionary

for i in z[1:]: #First record is our actual domain
    domainlist.append(i['domain'])
    reason.append(i['fuzzer'])
    
with open(filename, 'a',newline='') as file:
    writer = csv.writer(file)
    for i in domainlist:
        if i.replace(' ','') not in whitelist:
            try: #Try Converting the PunyCode (xn--)
                writer.writerow(["DomainName",i.encode('idna').decode('idna'),"","Block","","DNSTWIST",reason[domainlist.index(i)],"","","","","FALSE"])#Create MDE BlockList
            except: #fallback or apply additional logic (pending)
                print("ERROR" + i)
                #writer.writerow(["DomainName",i,"","DNSTWIST",reason[domainlist.index(i)],"","","","","FALSE"]) #MDE has limited Punycode support and TABL has none.
