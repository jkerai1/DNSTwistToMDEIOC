[![GitHub stars](https://img.shields.io/github/stars/jkerai1/DNSTwistToMDEIOC?style=flat-square)](https://github.com/jkerai1/DNSTwistToMDEIOC/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/jkerai1/DNSTwistToMDEIOC?style=flat-square)](https://github.com/jkerai1/DNSTwistToMDEIOC/network)
[![GitHub issues](https://img.shields.io/github/issues/jkerai1/DNSTwistToMDEIOC?style=flat-square)](https://github.com/jkerai1/DNSTwistToMDEIOC/issues)
[![GitHub pulls](https://img.shields.io/github/issues-pr/jkerai1/DNSTwistToMDEIOC?style=flat-square)](https://github.com/jkerai1/DNSTwistToMDEIOC/pulls)

# DNSTwistToMDEIOC
Convert DNSTwist Results to MDE IOCs then turn them into TenantAllowBlockLists ! This should run along aside Domain impersonation protection inside of Defender for Office (MDO). 

Can block typosquatters, phishing attacks, fraud, and brand impersonation!

![image](https://github.com/jkerai1/DNSTwistToMDEIOC/assets/55988027/d6c1f7f2-c72b-4b60-8519-8df07d3dc049)


# Result - (note needs xn-- encoding):  
![image](https://github.com/jkerai1/DNSTwistToMDEIOC/assets/55988027/f3df970e-cda3-4fa4-b921-bb44127ecd7b)

# How To install DNSTwist in Python  

Install DNSTwist using
<pre>
pip install dnstwist
</pre>
Reference: https://github.com/elceef/dnstwist

# How to Import  
![image](https://user-images.githubusercontent.com/55988027/279781043-db91bef8-7537-4aa8-afe2-e28eb6163717.png)

![image](https://github.com/jkerai1/DNSTwistToMDEIOC/assets/55988027/d889ad6a-dba2-481d-b8ab-cada3eb33f7e)


File naming convention is DNSTwist+{thedate}.csv

# General Usage  

No duplication checks between runs :) however MDE natively handles duplicates

Do not blindly upload, validate results before uploading  

Domains can be whitelisted by adding to the whitelist variable  

Extra domains to be twisted can be added to the domainsToTwist List  

# Whats Next?  

Block The Domain in Tenant Allow Block List using the powershell script (sender domain and URL)

TABL does not support punycode (xn--) and MDE support for punycode is limited. Defender for Office's impersonation list is hidden but TABL blocks will verify explictly domain is blocked.    

# Misc  
A good online punycode converter: https://www.punycoder.com/


# See also MDE IOC/TABL Repos for 
JoeSandBox: https://github.com/jkerai1/JoeSandBoxToMDEBlockList   
TLD: https://github.com/jkerai1/TLD-TABL-Block  
Ransomwatch: https://github.com/jkerai1/RansomWatchToMDEIoC/tree/main
