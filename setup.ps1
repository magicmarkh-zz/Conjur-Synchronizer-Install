#Add new file categories in vault - manual step
#activate CyberArk Vault Platform

[CmdletBinding(DefaultParametersetName = "Create")]
param
(
    [Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
    #[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("url")]
    [String]$PVWAURL,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$DisableSSLVerify
)

#check to see if service is already installed. If it is, exit immediately
$serviceInstalled = Get-Service CyberArkVaultConjurSynchronizer

if ($null -ne $serviceInstalled) {
    Write-Host "CyberArk Vault Conjur Synchronizer already installed. Nothing to do."
    exit
}

# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\Synchronizer_Install.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Global URLS
# -----------
$URL_PVWA_Base_API = $PVWAURL + "/PasswordVault/api"
$URL_PIM_Base_API = $PVWAURL + "/PasswordVault/WebServices/PIMServices.svc"

# API Methods
# -----------
$API_Logon = $URL_PVWA_Base_API + "/auth/cyberark/logon"
$API_Logoff = $URL_PVWA_Base_API + "/auth/logoff"
$API_VaultUsers = $URL_PIM_Base_API + "/Users"
$API_Platforms = $URL_PVWA_Base_API + "/Platforms"
$API_Platforms_Import = $API_Platforms + "/Import"
$API_Safes = $URL_PIM_Base_API + "/Safes"
$API_Accounts = $URL_PVWA_Base_API + "/accounts"

# Initialize Script Variables
# ---------------------------
$g_LogonHeader = ""

#region [Script Functions]
Function Get-IniContent {  
    <#  
    .Synopsis  
        Gets the content of an INI file  
          
    .Description  
        Gets the content of an INI file and returns it as a hashtable  
          
    .Notes  
        Author        : Oliver Lipkau <oliver@lipkau.net>  
        Blog        : http://oliver.lipkau.net/blog/  
        Source        : https://github.com/lipkau/PsIni 
                      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91 
        Version        : 1.0 - 2010/03/12 - Initial release  
                      1.1 - 2014/12/11 - Typo (Thx SLDR) 
                                         Typo (Thx Dave Stiff) 
          
        #Requires -Version 2.0  
          
    .Inputs  
        System.String  
          
    .Outputs  
        System.Collections.Hashtable  
          
    .Parameter FilePath  
        Specifies the path to the input file.  
          
    .Example  
        $FileContent = Get-IniContent "C:\myinifile.ini"  
        -----------  
        Description  
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent  
      
    .Example  
        $inifilepath | $FileContent = Get-IniContent  
        -----------  
        Description  
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent  
      
    .Example  
        C:\PS>$FileContent = Get-IniContent "c:\settings.ini"  
        C:\PS>$FileContent["Section"]["Key"]  
        -----------  
        Description  
        Returns the key "Key" of the section "Section" from the C:\settings.ini file  
          
    .Link  
        Out-IniFile  
    #>  
      
    [CmdletBinding()]  
    Param(  
        [ValidateNotNullOrEmpty()]  
        [ValidateScript( { (Test-Path $_) -and ((Get-Item $_).Extension -eq ".ini") })]  
        [Parameter(ValueFromPipeline = $True, Mandatory = $True)]  
        [string]$FilePath  
    )  
      
    Begin  
    { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started" }  
          
    Process {  
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"  
              
        $ini = @{}  
        switch -regex -file $FilePath {  
            "^\[(.+)\]$" {
                # Section    
                $section = $matches[1]  
                $ini[$section] = @{}  
                $CommentCount = 0  
            }  
            "^(;.*)$" {
                # Comment    
                if (!($section)) {  
                    $section = "No-Section"  
                    $ini[$section] = @{}  
                }  
                $value = $matches[1]  
                $CommentCount = $CommentCount + 1  
                $name = "Comment" + $CommentCount  
                $ini[$section][$name] = $value  
            }   
            "(.+?)\s*=\s*(.*)" {
                # Key    
                if (!($section)) {  
                    $section = "No-Section"  
                    $ini[$section] = @{}  
                }  
                $name, $value = $matches[1..2]  
                $ini[$section][$name] = $value  
            }  
        }  
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"  
        Return $ini  
    }  
          
    End  
    { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended" }  
}

Function Out-IniFile {  
    <#  
    .Synopsis  
        Write hash content to INI file  
          
    .Description  
        Write hash content to INI file  
          
    .Notes  
        Author        : Oliver Lipkau <oliver@lipkau.net>  
        Blog        : http://oliver.lipkau.net/blog/  
        Source        : https://github.com/lipkau/PsIni 
                      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91 
        Version        : 1.0 - 2010/03/12 - Initial release  
                      1.1 - 2012/04/19 - Bugfix/Added example to help (Thx Ingmar Verheij)  
                      1.2 - 2014/12/11 - Improved handling for missing output file (Thx SLDR) 
          
        #Requires -Version 2.0  
          
    .Inputs  
        System.String  
        System.Collections.Hashtable  
          
    .Outputs  
        System.IO.FileSystemInfo  
          
    .Parameter Append  
        Adds the output to the end of an existing file, instead of replacing the file contents.  
          
    .Parameter InputObject  
        Specifies the Hashtable to be written to the file. Enter a variable that contains the objects or type a command or expression that gets the objects.  
  
    .Parameter FilePath  
        Specifies the path to the output file.  
       
     .Parameter Encoding  
        Specifies the type of character encoding used in the file. Valid values are "Unicode", "UTF7",  
         "UTF8", "UTF32", "ASCII", "BigEndianUnicode", "Default", and "OEM". "Unicode" is the default.  
          
        "Default" uses the encoding of the system's current ANSI code page.   
          
        "OEM" uses the current original equipment manufacturer code page identifier for the operating   
        system.  
       
     .Parameter Force  
        Allows the cmdlet to overwrite an existing read-only file. Even using the Force parameter, the cmdlet cannot override security restrictions.  
          
     .Parameter PassThru  
        Passes an object representing the location to the pipeline. By default, this cmdlet does not generate any output.  
                  
    .Example  
        Out-IniFile $IniVar "C:\myinifile.ini"  
        -----------  
        Description  
        Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini  
          
    .Example  
        $IniVar | Out-IniFile "C:\myinifile.ini" -Force  
        -----------  
        Description  
        Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and overwrites the file if it is already present  
          
    .Example  
        $file = Out-IniFile $IniVar "C:\myinifile.ini" -PassThru  
        -----------  
        Description  
        Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and saves the file into $file  
  
    .Example  
        $Category1 = @{“Key1”=”Value1”;”Key2”=”Value2”}  
    $Category2 = @{“Key1”=”Value1”;”Key2”=”Value2”}  
    $NewINIContent = @{“Category1”=$Category1;”Category2”=$Category2}  
    Out-IniFile -InputObject $NewINIContent -FilePath "C:\MyNewFile.INI"  
        -----------  
        Description  
        Creating a custom Hashtable and saving it to C:\MyNewFile.INI  
    .Link  
        Get-IniContent  
    #>  
      
    [CmdletBinding()]  
    Param(  
        [switch]$Append,  
          
        [ValidateSet("Unicode", "UTF7", "UTF8", "UTF32", "ASCII", "BigEndianUnicode", "Default", "OEM")]  
        [Parameter()]  
        [string]$Encoding = "Unicode",  
 
          
        [ValidateNotNullOrEmpty()]  
        [ValidatePattern('^([a-zA-Z]\:)?.+\.ini$')]  
        [Parameter(Mandatory = $True)]  
        [string]$FilePath,  
          
        [switch]$Force,  
          
        [ValidateNotNullOrEmpty()]  
        [Parameter(ValueFromPipeline = $True, Mandatory = $True)]  
        [Hashtable]$InputObject,  
          
        [switch]$Passthru  
    )  
      
    Begin  
    { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started" }  
          
    Process {  
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing to file: $Filepath"  
          
        if ($append) { $outfile = Get-Item $FilePath }  
        else { $outFile = New-Item -ItemType file -Path $Filepath -Force:$Force }  
        if (!($outFile)) { Throw "Could not create File" }  
        foreach ($i in $InputObject.keys) {  
            if (!($($InputObject[$i].GetType().Name) -eq "Hashtable")) {  
                #No Sections  
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing key: $i"  
                Add-Content -Path $outFile -Value "$i=$($InputObject[$i])" -Encoding $Encoding  
            }
            else {  
                #Sections  
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing Section: [$i]"  
                Add-Content -Path $outFile -Value "[$i]" -Encoding $Encoding  
                Foreach ($j in $($InputObject[$i].keys | Sort-Object)) {  
                    if ($j -match "^Comment[\d]+") {  
                        Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing comment: $j"  
                        Add-Content -Path $outFile -Value "$($InputObject[$i][$j])" -Encoding $Encoding  
                    }
                    else {  
                        Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing key: $j"  
                        Add-Content -Path $outFile -Value "$j=$($InputObject[$i][$j])" -Encoding $Encoding  
                    }  
                      
                }  
                Add-Content -Path $outFile -Value "" -Encoding $Encoding  
            }  
        }  
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Writing to file: $path"  
        if ($PassThru) { Return $outFile }  
    }  
          
    End  
    { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended" }  
} 
function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
}

function Add-LogMsg {
    <#
.SYNOPSIS
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
        [String]$type = "Info"
    )

    If ($Header) {
        "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
        Write-Host "======================================="
    }
    ElseIf ($SubHeader) { 
        "------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
        Write-Host "------------------------------------"
    }

    $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
    $writeToFile = $true
    # Replace empty message with 'N/A'
    if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
    # Check the message type
    switch ($type) {
        "Info" {
            Write-Host $MSG.ToString()
            $msgToWrite += "[INFO]`t$Msg"
        }
        "Warning" {
            Write-Host $MSG.ToString() -ForegroundColor DarkYellow
            $msgToWrite += "[WARNING]`t$Msg"
        }
        "Error" {
            Write-Host $MSG.ToString() -ForegroundColor Red
            $msgToWrite += "[ERROR]`t$Msg"
        }
        "Debug" {
            if ($InDebug) {
                Write-Debug $MSG
                $msgToWrite += "[DEBUG]`t$Msg"
            }
            else { $writeToFile = $False }
        }
        "Verbose" {
            if ($InVerbose) {
                Write-Verbose $MSG
                $msgToWrite += "[VERBOSE]`t$Msg"
            }
            else { $writeToFile = $False }
        }
    }

    If ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
    If ($Footer) { 
        "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
        Write-Host "======================================="
    }
}

function Get-LogonHeader {
    param($logonCred)
    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username = $logonCred.username.Replace('\', ''); password = $logonCred.GetNetworkCredential().password } | ConvertTo-Json
    try {
        # Logon
        $logonToken = Invoke-RestMethod -Uri $API_Logon -Method "Post" -ContentType "application/json" -Body $logonBody
        Add-LogMsg -Type Debug -MSG "Successfully retrieved logon token."
    }
    catch {
        Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription
        $logonToken = ""
    }
    If ([string]::IsNullOrEmpty($logonToken)) {
        Add-LogMsg -Type Error -MSG "Logon Token is Empty - Cannot login"
        exit
    }

    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)

    return $logonHeader
}

function Invoke-Rest {
    param ($Command, $URI, $Header, $Body, $ErrorAction = "Continue")

    $restResponse = ""
    try {
        Add-LogMsg -Type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body"
        $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body
    }
    catch {
        If ($null -ne $_.Exception.Response.StatusDescription) {
            Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
        }
        else {
            Add-LogMsg -Type Error -Msg "StatusCode: $_.Exception.Response.StatusCode.value__"
        }
        $restResponse = $null
    }
    Add-LogMsg -Type Verbose -MSG $restResponse
    return $restResponse
}

function Get-VaultObject {
    param ($commandUri)
    $_vaultObject = $null
    try {
        $_vaultObject = $(Invoke-Rest -Uri $commandUri -Header $g_LogonHeader -Command "Get" -ErrorAction "SilentlyContinue")
    }
    catch {
        Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription
    }
    return $_vaultObject
}

function Get-RandomPassword() {

    Param(
    
        [int]$length = 32
    
    )
    
    $sourcedata = $null
    for ($a = 48; $a -le 110; $a++) {
        $sourcedata += , [char][byte]$a
    }
    for ($loop = 1; $loop -le $length; $loop++) {
        $TempPassword += ($sourcedata | Get-Random)
    }
    return $TempPassword
}


#endregion

# Check if to disable SSL verification
If ($DisableSSLVerify) {
    try {
        #Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
        # Using Proxy Default credentials if the Sevrer needs Proxy credentials
        [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        #  # Using TLS 1.2 as security protocol verification
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
        #   # Disable SSL Verification
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
    }
    catch {
        Add-LogMsg -Type Error -MSG "Could not change SSL validation"
        Add-LogMsg -Type Error -MSG $_.Exception
        exit
    }
}

If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
    Add-LogMsg -Type Error -MSG  "This script requires Powershell version 3 or above"
    exit
}

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL)) {
    If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
        $PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
    }

    try {
        # Validate PVWA URL is OK
        Add-LogMsg -Type Debug -MSG  "Trying to validate URL: $PVWAURL"
        Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
    }
    catch [System.Net.WebException] {
        If (![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__)) {
            Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusCode.Value__
        }
    }
    catch {
        Add-LogMsg -Type Error -MSG "PVWA URL could not be validated"
        Add-LogMsg -Type Error -MSG $_.Exception
    }
}
else {
    Add-LogMsg -Type Error -MSG "PVWA URL can not be empty"
    exit
}

#Logon to vault
#region [Logon]
# Get Credentials to Login
# ------------------------
$title = "Vault Synchronizer Installation"
$msg = "Enter your User name and Password";
$creds = $Host.UI.PromptForCredential($title, $msg, "", "")
if ($null -ne $creds) {
    $g_LogonHeader = $(Get-LogonHeader $creds)
}
else {
    Add-LogMsg -Type Error -MSG "No Credentials were entered" -Footer
    exit
}
	
#endregion


#region [Create EPV User]
#Test for existing vault user and create if it doesn't exist
try {
    $vaultSyncUserName = "Sync_" + $env:COMPUTERNAME
    $userUri = $API_VaultUsers + '/' + $vaultSyncUserName
    if ($null -eq $(Get-VaultObject $userUri )) {
        #User does not exist, so we need to create one
        $vaultUserInitialPassword = Get-RandomPassword 
        $createUserBody = @{ UserName = $vaultSyncUserName; InitialPassword = $vaultUserInitialPassword; ChangePasswordOnTheNextLogon = $false; UserTypeName = "AppProvider"; Disabled = $false } | ConvertTo-Json
        if ($null -ne $(Invoke-Rest -Command Post -URI $API_VaultUsers -Header $g_LogonHeader -Body $createUserBody)) {
                    
            Add-LogMsg -type Info -MSG "EPV User Account $($vaultSyncUserName) successfully created."
        } 
        else {
            Add-LogMsg -type Error -MSG "EPV User Account $($vaultSyncUserName) could not be created."
        }
    }   
    else {
        #Write to log that the user already exists
        Add-LogMsg -type Info -MSG "Vault User Sync_$($env:COMPUTERNAME) already exists, will not create vault user."
    }
}
catch {
    Add-LogMsg -type Error -MSG $_.Exception
}
#endregion

#region [Create ConjurSync Safe]
#Check to see if conjur host platform exists and upload if it doesn't
try {
    $conjurSyncSafeUri = $API_Safes + "?query=ConjurSync"
    if ($null -ne $(Get-VaultObject $conjurSyncSafeUri )) {
        #Safe does not exist, so we need to create one

        #create the JSON Body to upload the platform with
        $newSafeBody = @{ safe = @{Description = "Conjur Synchronizer Safe"; ManagingCPM = "PasswordManager"; SafeName = "ConjurSync"; OLACEnabled = $false } } | ConvertTo-JSON
        if ($null -ne $(Invoke-Rest -Command Post -URI $API_Safes -Header $g_LogonHeader -Body $newSafeBody)) {
                    
            Add-LogMsg -type Info -MSG "ConjurSync Safe successfully created."
        } 
        else {
            Add-LogMsg -type Error -MSG "ConjurSync Safe could not be created."
        }
    }   
    else {
        #Write to log that the safe already exists
        Add-LogMsg -type Info -MSG "ConjurSync safe already exists, will not create a new safe."
    }
}
catch {
    Add-LogMsg -type Error -MSG $_.Exception
}
#endregion

#region [Add Vault User created above to ConjurSync Safe]
#List Safe members, parse to see if user above exists If it doesn't, Add, if it does, Update permissions
try {
    $listSafeMemberUri = $API_Safes + "/ConjurSync/Members"

    #Get JSON Response of ConjurSync Safe Members
    $safeMemberResult = Get-VaultObject $listSafeMemberUri
    $safeMembershipExists = $false

    #loop through JSON response to see if the vault user from above is already a member
    foreach ($safeMember in $safeMemberResult.members) {
        if ($safeMember.UserName -eq $vaultSyncUserName)
        { $safeMembershipExists = $true }
    }

    if ($safeMembershipExists -eq $false) {
        #Add the safe member
        $newSafeMemberBody = @{member =
            @{MemberName                 = $vaultSyncUserName
                SearchIn                 = "Vault"
                MembershipExpirationDate = ""
                Permissions              = @(
                    @{Key     = "UseAccounts"
                        Value = $true
                    },
                    @{Key     = "RetrieveAccounts"
                        Value = $true
                    },
                    @{Key     = "ListAccounts"
                        Value = $true
                    },
                    @{Key     = "AddAccounts"
                        Value = $true
                    },
                    @{Key     = "UpdateAccountContent"
                        Value = $true
                    },
                    @{Key     = "UpdateAccountProperties"
                        Value = $true
                    },
                    @{Key     = "InitiateCPMAccountManagementOperations"
                        Value = $true
                    },
                    @{Key     = "SpecifyNextAccountContent"
                        Value = $false
                    },
                    @{Key     = "RenameAccounts"
                        Value = $false
                    },
                    @{Key     = "DeleteAccounts"
                        Value = $false
                    },
                    @{Key     = "UnlockAccounts"
                        Value = $false
                    },
                    @{Key     = "ManageSafe"
                        Value = $false
                    },
                    @{Key     = "ManageSafeMembers"
                        Value = $false
                    },
                    @{Key     = "BackupSafe"
                        Value = $false
                    },
                    @{Key     = "ViewAuditLog"
                        Value = $false
                    },
                    @{Key     = "ViewSafeMembers"
                        Value = $false
                    },
                    @{Key     = "RequestsAuthorizationLevel"
                        Value = 1
                    },
                    @{Key     = "AccessWithoutConfirmation"
                        Value = $true
                    },
                    @{Key     = "CreateFolders"
                        Value = $true
                    },
                    @{Key     = "DeleteFolders"
                        Value = $true
                    },
                    @{Key     = "MoveAccountsAndFolders"
                        Value = $false
                    }
                )
            }
        } | ConvertTo-Json -Depth 3
            
        $addSafeMemberUri = $API_Safes + "/ConjurSync/Members"
        if ($null -ne $(Invoke-Rest -Command Post -URI $addSafeMemberUri -Header $g_LogonHeader -Body $newSafeMemberBody)) {
                    
            Add-LogMsg -type Info -MSG "User $($vaultSyncUserName) permissions successfully created for ConjurSync Safe."
        } 
        else {
            Add-LogMsg -type Error -MSG "User $($vaultSyncUserName) could not be added to ConjurSync Safe."
        }
    }
    else {
        #update safe permissions to ensure Sync User has appropriate permissions
        $updateSafeMemberBody = @{member =
            @{
                MembershipExpirationDate = ""
                Permissions              = @(
                    @{Key     = "UseAccounts"
                        Value = $true
                    },
                    @{Key     = "RetrieveAccounts"
                        Value = $true
                    },
                    @{Key     = "ListAccounts"
                        Value = $true
                    },
                    @{Key     = "AddAccounts"
                        Value = $true
                    },
                    @{Key     = "UpdateAccountContent"
                        Value = $true
                    },
                    @{Key     = "UpdateAccountProperties"
                        Value = $true
                    },
                    @{Key     = "InitiateCPMAccountManagementOperations"
                        Value = $true
                    },
                    @{Key     = "SpecifyNextAccountContent"
                        Value = $false
                    },
                    @{Key     = "RenameAccounts"
                        Value = $false
                    },
                    @{Key     = "DeleteAccounts"
                        Value = $false
                    },
                    @{Key     = "UnlockAccounts"
                        Value = $false
                    },
                    @{Key     = "ManageSafe"
                        Value = $false
                    },
                    @{Key     = "ManageSafeMembers"
                        Value = $false
                    },
                    @{Key     = "BackupSafe"
                        Value = $false
                    },
                    @{Key     = "ViewAuditLog"
                        Value = $false
                    },
                    @{Key     = "ViewSafeMembers"
                        Value = $false
                    },
                    @{Key     = "RequestsAuthorizationLevel"
                        Value = 1
                    },
                    @{Key     = "AccessWithoutConfirmation"
                        Value = $true
                    },
                    @{Key     = "CreateFolders"
                        Value = $true
                    },
                    @{Key     = "DeleteFolders"
                        Value = $true
                    },
                    @{Key     = "MoveAccountsAndFolders"
                        Value = $false
                    }
                )
            }
        } | ConvertTo-Json -Depth 3
            
        $updateSafeMemberUri = $API_Safes + "/ConjurSync/Members/" + $vaultSyncUserName
        if ($null -ne $(Invoke-Rest -Command Post -URI $updateSafeMemberUri -Header $g_LogonHeader -Body $updateSafeMemberBody)) {
                    
            Add-LogMsg -type Info -MSG "User $($vaultSyncUserName) permissions successfully updated for ConjurSync Safe."
        } 
        else {
            Add-LogMsg -type Error -MSG "User $($vaultSyncUserName) could not be updated for ConjurSync Safe."
        }
    }
}
catch {
    Add-LogMsg -type Error -MSG $_.Exception
}

#endregion

#region [Update permissions on PVWA Config safe]
if ($safeMembershipExists -eq $false) {
    #Add the safe member
    $newSafeMemberBody = @{member =
        @{MemberName                 = $vaultSyncUserName
            SearchIn                 = "Vault"
            MembershipExpirationDate = ""
            Permissions              = @(
                @{Key     = "UseAccounts"
                    Value = $false
                },
                @{Key     = "RetrieveAccounts"
                    Value = $true
                },
                @{Key     = "ListAccounts"
                    Value = $true
                },
                @{Key     = "AddAccounts"
                    Value = $false
                },
                @{Key     = "UpdateAccountContent"
                    Value = $false
                },
                @{Key     = "UpdateAccountProperties"
                    Value = $false
                },
                @{Key     = "InitiateCPMAccountManagementOperations"
                    Value = $false
                },
                @{Key     = "SpecifyNextAccountContent"
                    Value = $false
                },
                @{Key     = "RenameAccounts"
                    Value = $false
                },
                @{Key     = "DeleteAccounts"
                    Value = $false
                },
                @{Key     = "UnlockAccounts"
                    Value = $false
                },
                @{Key     = "ManageSafe"
                    Value = $false
                },
                @{Key     = "ManageSafeMembers"
                    Value = $false
                },
                @{Key     = "BackupSafe"
                    Value = $false
                },
                @{Key     = "ViewAuditLog"
                    Value = $false
                },
                @{Key     = "ViewSafeMembers"
                    Value = $false
                },
                @{Key     = "RequestsAuthorizationLevel"
                    Value = 1
                },
                @{Key     = "AccessWithoutConfirmation"
                    Value = $true
                },
                @{Key     = "CreateFolders"
                    Value = $false
                },
                @{Key     = "DeleteFolders"
                    Value = $false
                },
                @{Key     = "MoveAccountsAndFolders"
                    Value = $false
                }
            )
        }
    } | ConvertTo-Json -Depth 3
            
    $addSafeMemberUri = $API_Safes + "/PVWAConfig/Members"
    if ($null -ne $(Invoke-Rest -Command Post -URI $addSafeMemberUri -Header $g_LogonHeader -Body $newSafeMemberBody)) {
                    
        Add-LogMsg -type Info -MSG "User $($vaultSyncUserName) permissions successfully created for PVWAConfig Safe."
    } 
    else {
        Add-LogMsg -type Error -MSG "User $($vaultSyncUserName) could not be added to PVWAConfig Safe."
    }
}
#endregion

#region [Locate and Expand Install Package Archive]
#installation package title must contain Vault Conjur Synchronizer and be a .zip file
    
$installPackageZip = Get-ChildItem -Path $ScriptLocation -Name *.zip
if ($null -ne $installPackageZip) {
    Expand-Archive $installPackageZip
    Add-LogMsg -type Info -MSG "Vault Conjur Synchronizer install package located and successfully extracted."
}
else {
    Add-LogMsg -type Error -MSG "Vault Conjur Synchronizer install package could not be located. Installation cannot proceed."
    exit
}

#endregion

#region [Upload Conjur Platform]
#Check to see if conjur host platform exists and upload if it doesn't
try {
    $platformUri = $API_Platforms + '/ConjurHost'
    if ($null -eq $(Get-VaultObject $platformUri )) {
        #Platform does not exist, so we need to create one
        
        #locate the platform and convert to base64
        $conjurHostPlatformFile = Get-ChildItem -Path $ScriptLocation -Recurse -Include Policy-ConjurHost.zip 
        $base64ConjurHostPlatform = [Convert]::ToBase64String([IO.File]::ReadAllBytes($conjurHostPlatformFile.DirectoryName + "/" + $conjurHostPlatformFile.Name))

        #create the JSON Body to upload the platform with
        $createPlatformBody = @{ ImportFile = $base64ConjurHostPlatform } | ConvertTo-Json
        if ($null -ne $(Invoke-Rest -Command Post -URI $API_Platforms_Import -Header $g_LogonHeader -Body $createPlatformBody)) {
                    
            Add-LogMsg -type Info -MSG "Conjur Host Platform successfully created."
        } 
        else {
            Add-LogMsg -type Error -MSG "Conjur Host Platform could not be created."
        }
    }   
    else {
        #Write to log that the platform already exists
        Add-LogMsg -type Info -MSG "ConjurHost platform already exists, will not upload new ConjurHost platform."
    }
}
catch {
    Add-LogMsg -type Error -MSG $_.Exception
}
#endregion

#region [Synchronizer Installation Prep]

Write-Host ""

#Specify Conjur Username
if (($conjurUser = Read-Host -Prompt "Enter the Conjur username with permissions to add a host [admin]") -eq "") { $conjurUser = "admin" }else { $conjurUser }
#Specify Conjur User Password
Do { $conjurUserPassword = Read-Host -Prompt "Enter the Conjur User's Password" -AsSecureString }Until($conjurUserPassword.Length -ge 1)
#Specify Conjur Install Path
if (($synchronizerInstallPath = Read-Host -Prompt "Specify Vault-Conjur Synchronizer installation target path [C:\Program Files\CyberArk\Synchronizer]") -eq "") { $synchronizerInstallPath = "C:\Program Files\CyberArk\Synchronizer" }else { $synchronizerInstallPath }
#specify Conjur DNS Name
Do { $conjurServerDNS = Read-Host -Prompt "Conjur server hostname (and optional port in the format of hostname[:port])" }Until($conjurServerDNS.Length -ge 1)
#Specify CyberArk Vault Name
if (($vaultName = Read-Host -Prompt "Enter the CyberArk Vault Name [epv]") -eq "") { $vaultName = "epv" }else { $vaultName }
#specify IP Address of EPV Vault
Do { $vaultIPAddress = Read-Host -Prompt "Enter the CyberArk Vault IP Address" }Until($vaultIPAddress -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
# Specify Vault port. By default 1858 
if (($vaultPort = Read-Host -Prompt "Enter the CyberArk Vault Port [1858]") -eq "") { $vaultPort = "1858" }else { $vaultPort }
#Specify Conjur Account Name
Do { $conjurAccountName = Read-Host -Prompt "Enter the Conjur Account Name" }Until($conjurAccountName.Length -ge 1)

#now create a cred file for the conjur user.
$installFolderPath = Get-ChildItem -Include Installation -Recurse -Directory
$conjurCredFileDestination = $installFolderPath.FullName + "ConjurAdminCredFile.xml"
$conjurCredFile = New-Object System.Management.Automation.PSCredential -ArgumentList $conjurUser, $conjurUserPassword
$conjurCredFile | Export-Clixml $conjurCredFileDestination
#$conjurCredFileLocation = Get-ChildItem -Name ConjurAdminCredFile.xml -Path $ScriptLocation -Recurse

#update the silent.ini file with parameters entered above
#find the silent.ini file
$silentIniFile = Get-ChildItem -Recurse -Name silent.ini -Path $ScriptLocation
#load the contents into a variable
$newIniFile = Get-IniContent -FilePath $silentIniFile
#Update values
$newIniFile["Main"]["InstallationTargetPath"] = $synchronizerInstallPath
$newIniFile["Main"]["ConjurServerDNS"] = $conjurServerDNS
$newIniFile["Main"]["VaultName"] = $vaultName
$newIniFile["Main"]["VaultAddress"] = $vaultIPAddress
$newIniFile["Main"]["VaultPort"] = $vaultPort
$newIniFile["Main"]["SynchronizerVaultUsername"] = $vaultSyncUserName
$newIniFile["Main"]["ConjurCredentialsFilePath"] = $conjurCredFileDestination
$newIniFile["Main"]["ConjurAccount"] = $conjurAccountName

#now write to a new ini file
$newIniFile | Out-IniFile -FilePath $silentIniFile -Force

#endregion

#region [Run Silet Synchronizer Installation]
if ($DisableSSLVerify -eq $true) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }

Get-ChildItem -Recurse -Name V5SynchronizerInstallation.ps1 -File -Path $ScriptLocation | ForEach-Object { &$_ -silent }

#endregion

#region [Create Conjur Host in CYBR]

if ($DisableSSLVerify -eq $true) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify } }

try {
    #Future Feature - Search for Account before adding. 
    $conjurHostCredentialsPath = Get-ChildItem -Name synchronizerConjurHost.xml -File -Path $ScriptLocation -Recurse
    $conjurHostCredentials = Import-Clixml -Path $conjurHostCredentialsPath

    $newAccountBody = @{ platformId = "ConjurHost"; safeName = "ConjurSync"; secretType = "password"; secret = $conjurHostCredentials.GetNetworkCredential().password; platformAccountProperties = @{ ConjurAccount = $conjurAccountName; HostName = $conjurHostCredentials.UserName; ApplianceURL = "https://" + $conjurServerDNS } } | ConvertTo-Json
    if ($null -ne $(Invoke-Rest -Command Post -URI $API_Accounts -Header $g_LogonHeader -Body $newAccountBody)) {
                    
        Add-LogMsg -type Info -MSG "Conjur Host $($conjurHostCredentials.Username) successfully added to CyberArk EPV."
    } 
    else {
        Add-LogMsg -type Error -MSG "Conjur Host $($conjurHostCredentials.Username) could not be created in CyberArk EPV."
    }
}
catch {
    Add-LogMsg -type Error -MSG $_.Exception
}

#endregion


#region [Start Service]
#Create Cred file for Conjur Synchronizer Vault User

$credFilePath = $synchronizerInstallPath + "\Vault\VaultConjurSynchronizerUser.cred"
Get-ChildItem -Name CreateCredFile.exe -File -Path $ScriptLocation -Recurse | ForEach-Object { &$_ $credFilePath Password /username $vaultSyncUserName /password $vaultUserInitialPassword }

Start-Service -Name CyberArkVaultConjurSynchronizer

$syncSvc = Get-Service -Name CyberArkVaultConjurSynchronizer

if ($syncSvc.Status -eq "Running") {
    Add-LogMsg -type Info -MSG "CyberArk Vault Conjur Synchronizer service successfully started."
    #clean up the install directory
    Get-ChildItem -Name Vault* -Directory | Remove-Item -Force -Recurse
    Write-Host "Vault Conjur Synchronizer Install Successful"
}
else {
    Add-LogMsg -type Error -MSG "CyberArk Vault Conjur Synchronizer service failed to start."
}

#endregion





#region [Logoff]
# Logoff the session
# ------------------
Invoke-Rest -Uri $API_Logoff -Header $g_LogonHeader -Command "Post"
# Footer

#endregion
