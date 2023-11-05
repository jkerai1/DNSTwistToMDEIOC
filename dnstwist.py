import os
import csv
import dnstwist #pip install this
import datetime
from pathlib import Path

domainlist = []
reason =[]

query = input("Domain to twist? ")
if query == "":
    query = "microsoft.com" #FallBack

IOC_Columns = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"]
stamp = datetime.datetime.now().strftime("%x").replace("/","-")
filename = "DNSTwist+" + query + stamp + ".csv"

if os.path.exists(filename)== False:
    with open(filename, 'a+',newline='') as file:
        writer = csv.writer(file)
        writer.writerow(IOC_Columns)

z = dnstwist.run(domain=query, format = 'csv')

for i in z:
    domainlist.append(i['domain'])
    reason.append(i['fuzzer'])
    
domainlist.remove(query)
reason.remove("*original") # Remove our actual domain from the list
            
with open(filename, 'a',newline='') as file:
    writer = csv.writer(file)
    for i in domainlist:#DomainName
        writer.writerow(["DomainName",i,"","Block","","DNSTWIST",reason[domainlist.index(i)],"","","","","FALSE"])#Create MDE BlockList
