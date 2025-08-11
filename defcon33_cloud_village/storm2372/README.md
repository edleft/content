# Summary
- This recreates Dirk Jan's demos of Windows Hello For Business PRT attack that he has
  presented at numerous conferences. This was against Entra ID with a fictitious device
  (in testing, attack was carried out from Mac)
- The front-end device code phish is done by demo.ps1, a variation on @DrAzureAD's original
  set of scripts referenced: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
- Powershell demo.ps1 does not use any modules, just straight Invoke Rest Method for clarity.
  Attempts to print payload. pwsh on macos and linux work fine.
- Dirk Jan's roadtx is used for all the WFHB/PRT attacks, the meat of the Storm attack
  - roadtx: https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)
- The scripts call out to pwsh, assuming a non-Windows Powershell install (mac or linux). Windows works fine but executable names/paths will need change.

# Prerequisites
- Powershell installed
- ROADtx installed

# Install/Config Notes
- Install roadtx properly, best to use virtual env for isolation
- Make sure roadtx executable in path
- If using a proxy for analysis some of the Selenium launch by roadtx. Did not have time
    to full troubleshoot.
- Copy demo.json.tmpl and fill in SMTP server with proper server that takes user/pass
    Note: Believe Microsoft has secured their O365 SMTP to require OAuth and no longer support
    simpler user/pass (app pwds). Gmail still works. Fastmail as well. Sender domain should
    match. The usual.
- roadtx.sh is the main demo script
    - runs demo.ps1 then roadtx, a little hackey in storing token files for roadtx 
    - roadtx can take tokens on cmd-line but the current demo.ps1 does some hacky stuff of creating a token file for roadtx in the right format. cleanup for later
- set USER in roadtx.sh to victim username 
- set $tenant_id in demo.ps1 to victim tenant id

# Run
1. Make sure roadtx is in your path
2. Run: roadtx.sh
3. Respond to phishing attack email (victim inbox) with authorization. Use new session and login with MFA.
4. Clean up artifacts in Entra
    - device registration (attacker-host)
    - user > authentication methods > Windows Hello For Business

# Attack Flow

![](img/Slide1.png)
![](img/Slide2.png)
![](img/Slide3.png)
![](img/Slide4.png)
![](img/Slide5.png)
![](img/Slide6.png)
![](img/Slide7.png)
![](img/Slide8.png)
![](img/Slide9.png)
![](img/Slide10.png)
![](img/Slide11.png)
![](img/Slide12.png)
![](img/Slide13.png)
![](img/Slide14.png)
![](img/Slide15.png)
![](img/Slide16.png)
![](img/Slide17.png)
![](img/Slide18.png)
![](img/Slide19.png)
![](img/Slide20.png)
![](img/Slide21.png)

# Storm 2372 
- Microsoft advisory
  https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
- Dirk Jan Mollema did the most relevant TTP analysis in Oct 2023
  https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
- Dirk Jan has presented this demo
- Dirk Jan's roadtx toolset is used in this demo

# Device Code Phishing
- Most relevant work is
  Dr. Nestori Syynimaa: https://o365blog.com/post/phishing
- Netskope BSD-3 clause is based on @DrAzureAD work 
  https://github.com/netskopeoss/phish_oauth/blob/master/device_code/pwsh/demo_msft.ps1

# Acknowledgments
- https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
- Dr. Nestori Syynimaa: https://o365blog.com/post/phishing
- https://github.com/netskopeoss/phish_oauth/blob/master/device_code/pwsh/demo_msft.ps1

