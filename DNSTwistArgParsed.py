import os
import csv   
import argparse                                                                          #Tool Written by Jkerai1 https://github.com/jkerai1
import dnstwist #pip install this
import datetime
from pathlib import Path

def main():
    domainsToTwist = [] #add additional domains to twist here
    parser = argparse.ArgumentParser(description="Domain twisting script")
    parser.add_argument('--domaininput', type=str, default="google.com", help='Domain to twist')
    args = parser.parse_args()
    
    domain_temp = args.domaininput
    whitelist =["example.com"] #domains to exclude from blocking
    domainlist = []
    reason =[]
    domainsToTwist.append(domain_temp)

    IOC_Columns = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"]
    stamp = datetime.datetime.now().strftime("%x").replace("/","-")
    filename = "DNSTwist " + domainsToTwist[-1] + stamp + ".csv"

    if os.path.exists(filename)== False:
        with open(filename, 'a+',newline='',encoding='utf-8') as file: #Build new file in append mode
            writer = csv.writer(file)
            writer.writerow(IOC_Columns)

    for query in domainsToTwist:        
        z = dnstwist.run(domain=query, format = 'csv')#,tld = 'TLDextended.dict')#,dictionary = 'english.dict') - use following to extend TLDs or Dictionary

        for i in z[1:]: #First record is our actual domain
            domainlist.append(i['domain'])
            reason.append(i['fuzzer'])
            
    with open(filename, 'a',newline='') as file:
        writer = csv.writer(file)
        for i in domainlist:
            if i.replace(' ','') not in whitelist:
                try: #Try Converting the PunyCode (xn--)
                    print(i.encode('idna').decode('idna'))
                    writer.writerow(["DomainName",i,"","Block","","Dnstwist "+ reason[domainlist.index(i)],"Reason for DNSTwist Block: " + reason[domainlist.index(i)] + "\nTool written by jkerai1","","","","","FALSE"])#Create MDE BlockList
                #writer.writerow(["DomainName",i.encode('idna').decode('idna'),"","Block","","Dnstwist "+ reason[domainlist.index(i)],"Reason for DNSTwist Block: " + reason[domainlist.index(i)] + "\nTool written by jkerai1","","","","","FALSE"])#Create MDE BlockList
                except: #fallback
                    print("   PunyCode fallback- cannot add to CSV: " + i.encode('idna').decode('idna'))

if __name__ == "__main__":
    main()
