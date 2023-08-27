<#----------------------------------------------------------------------------------------------------------
<DEVELOPMENT>
------------------------------------------------------------------------------------------------------------
    > Created: 23-06-06 | TawTek
    > Updated: 23-08-26 | TawTek
    > Version: 3.0
------------------------------------------------------------------------------------------------------------
<DESCRIPTION> Removes local user account from account databse, profile directory, and registry keys
------------------------------------------------------------------------------------------------------------
    > Specify username in parameters
    > Checks if user account exists, terminates if not
    > If user account exists, will remove it from account database, profile directory, and registry
------------------------------------------------------------------------------------------------------------
<CHANGELOG>
------------------------------------------------------------------------------------------------------------
    > 23-06-06  Developed first iteration of script
    > 23-07-26  Added if/else to check if user account exists to have cleaner error handling
                Cleaned up script formatting and descriptions
    > 23-08-26  Revised script formatting to new standardization
------------------------------------------------------------------------------------------------------------
<GITHUB>
----------------------------------------------------------------------------------------------------------#>

#-Parameters
param(
    [string] $Username
)

#-Variables
$VerbosePreference = "Continue"
$EA_Silent = @{ErrorAction = "SilentlyContinue"}
$EA_Stop   = @{ErrorAction = "Stop"}
$User = Get-LocalUser -Name $Username @EA_Silent

<#------------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
------------------------------------------------------------------------------------------------------------#>

##--Checks if user account exists
function Test-User {
    if ($Username) {
        Write-Verbose "Checking if $Username exists."
        if (-not $User) {
            Write-Verbose "$Username does not exist. Terminating script."
            exit
        } else {
            Write-Verbose "$Username exists, removing account."
        }
    } else {
        Write-Verbose "No Username defined. Input Username in parameter field and rerun script."
        exit
    }
}

##--Removes account from database, profile directory, and associated registry keys
function Remove-User {
    Write-Verbose "Removing user account from account database."
    Remove-LocalUser -SID $User.SID
    Write-Verbose "Removing user account profile directory and associated registry keys."
    Get-CimInstance -Class Win32_UserProfile | ? SID -eq $User.SID | Remove-CimInstance
    Write-Verbose "The user account $Username has been deleted."
}

<#------------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
------------------------------------------------------------------------------------------------------------#>

Test-User
Remove-User
