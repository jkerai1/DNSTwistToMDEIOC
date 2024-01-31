# DNSTwistToMDEIOC
Convert DNSTwist Results to MDE IOCs then turn them into TenantAllowBlockLists ! This should run along aside Domain impersonation protection inside of Defender for Office (MDO). 

Can block typosquatters, phishing attacks, fraud, and brand impersonation!

Install DNSTwist using
<pre>
pip install dnstwist
</pre>
Reference: https://github.com/elceef/dnstwist

# How to Import  
![image](https://user-images.githubusercontent.com/55988027/279781043-db91bef8-7537-4aa8-afe2-e28eb6163717.png)

![image](https://github.com/jkerai1/DNSTwistToMDEIOC/assets/55988027/d889ad6a-dba2-481d-b8ab-cada3eb33f7e)


File naming convention is DNSTwist+{thedate}.csv

#General Usage  

No duplication checks between runs :) however MDE natively handles duplicates

Do not blindly upload, validate results before uploading  

Domains can be whitelisted by adding to the whitelist variable  

Extra domains to be twisted can be added to the domainsToTwist List  

# Whats Next?  

Block The Domain in Tenant Allow Block List using the powershell script (sender domain and URL)

TABL does not support punycode (xn--) and MDE support for punycode is limited. Defender for Office's impersonation list is hidden but TABL blocks will verify explictly domain is blocked.    

# Misc  
A good online punycode converter: https://www.punycoder.com/
