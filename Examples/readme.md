# Example Files 

Note there is a 500 upload limit #TODO automatic rollover  

There is a limit of 500 IOCs per CSV in MDE, if you need to split out the IOCs, please see: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Scripts/MDE-IOC-Batch-Separator.py

# Example Usage with KQL

```
//TypoSquatted Crowdstrike Domains ref: https://github.com/jkerai1/DNSTwistToMDEIOC/
let CrowdstrikeTypoSquats = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/DNSTwistToMDEIOC/main/Examples/DNSTwist%20crowdstrike.com07-22-24.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = CrowdstrikeTypoSquats
| project IndicatorValue;
let emailurl = EmailUrlInfo
| where UrlDomain in~(DomainList)
| join EmailEvents on NetworkMessageId;
let emailevent = EmailEvents
| where SenderFromDomain in~(DomainList);
DeviceNetworkEvents
| where RemoteUrl in~(DomainList )
| union emailurl, emailevent

```
