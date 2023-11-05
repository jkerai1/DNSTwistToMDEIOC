import os
import csv
import dnstwist #pip install this
import datetime
from pathlib import Path

whitelist =["example.com"]
domainlist = []
reason =[]

query = input("Domain to twist? ")
if query == "":
    query = "microsoft.com" #FallBack  #whitelist.append(query)

IOC_Columns = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"]
stamp = datetime.datetime.now().strftime("%x").replace("/","-")
filename = "DNSTwist " + query + stamp + ".csv"

if os.path.exists(filename)== False:
    with open(filename, 'a+',newline='') as file:
        writer = csv.writer(file)
        writer.writerow(IOC_Columns)

z = dnstwist.run(domain=query, format = 'csv')

for i in z[1:]: #First record is our actual domain
    domainlist.append(i['domain'])
    reason.append(i['fuzzer'])
    
with open(filename, 'a',newline='') as file:
    writer = csv.writer(file)
    for i in domainlist:
        if i.replace(' ','') not in whitelist:
            writer.writerow(["DomainName",i,"","Block","","DNSTWIST",reason[domainlist.index(i)],"","","","","FALSE"])
