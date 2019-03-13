# CyberArk Vault Conjur Install Script

This script will install the CyberArk Vault Conjur Synchronizer service

## Requirements

1. You must have a working version of CyberArk Conjur Enterprise V5.x
2. DNS Record matching the conjur master certificate
3. Conjur Synchronizer Install zip file

## How To Use

1. Create a directory and place the setup.ps1 script on the synchronizer server
2. Place the CyberArk Synchronizer Installer package in the same directory, do not unzip
3. Open an administrative PowerShell prompt and navigate to the directory created in step 1
4. If ConjurHost platform already exists in your environment, ensure that the platform is active
5. run .\setup.ps1
   i. If you do not have valid certificates, use the -DisableVerify switch
   ii. Specify the CyberArk EPV Web portal address with -PVWAURL httsp://server.yourcompany.com

## Information to be entered

1. At popup box, enter credentials to log into the CyberArk EPV Web Portal
2. Conjur Username with permission to add host is a Conjur Account that can add a host. Default is the admin user.
3. Conjur Users's Password is the password for the account mentioned in step 2
4. Conjur Install Path. This defaults to c:\Program Files, and can be changed. Press enter to accept the default path.
5. CyberArk vault name is a friendly name for your EPV Vault. Press enter to accept the default value.
6. Conjur server hostname is the DNS name of your conjur installation. This must match the certificate for your Conjur instance. Do not include https. Only include the port if it is something other than 443. Ex: If your Conjur server is named acme-conjur and it answers on 443, you would only enter 'acme-conjur'. If it answers on port 445, you would enter acme-conjur:445"
7. IP Address of EPV vault is the IP address of the primary vault machine.
8. Vault Port is the port the CyberArk EPV vault accept communication traffic on.
9. Conjur Account name is the Account name specified in conjur. This is defined during Conjur setup. If you do not know the account name, run "conjur list" from the conjur-cli container to find the account name. It is the first word/name for all policies, variables, etc... for the account.

## Known Issues

- Some older versions of PowerShell will not extract the installer although the shell will indicate it has been extracted. Once the script stops to ask for information, if the zip file has not been sucessfully extracted, you shoudl manually extract it at this time.

## Limitations

- Does not check for already existing Conjur Host in EPV
- Conjur Enterprise V5.x only
- Does not currently allow user to enter password for previously existing EPV Conjur Host, will fail to start service

## Post Installation

- LOB Users must be created manually to sync certain safes with Conjur