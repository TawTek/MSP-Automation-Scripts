###Parameters
param(
    [string]$Name=''
)

###Variables
$Info = {
*************************************************************************************************************************
* Synopsis: Script to remove local user account
* Description:

    >Removes local user account which is specified in the Ninja Script Parameter. It will remove it from the 
     account database as well as any associated registry keys

*  Created: 23-06-06 by TawTek
*  Updated: 23-06-06 by TawtTek
*  Version: 1.0
*************************************************************************************************************************
}
$User = Get-LocalUser -Name $Name -ErrorAction stop

function Remove-LocalUserAccount {
    Write-Host $Info
    # Remove the user from the account database
    Remove-LocalUser -SID $User.SID
    # Remove the profile of the user (both, profile directory and profile in the registry)
    Get-CimInstance -Class Win32_UserProfile | ? SID -eq $User.SID | Remove-CimInstance
    Write-Host "The user account $Name has been removed along with corresponding registry keys"
}

Remove-LocalUserAccount