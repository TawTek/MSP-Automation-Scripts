#---Parameters
param(
    [string] $NewUser,
    [string] $Group,
    [string] $Password,
    [string] $AdministratorDisabled
)
#---Variables [General]
$Info = {
**********************************************************************************************************
*  SYNOPSIS: Create new local user account
*  DESCRIPTION:

    > Specify parameters for new user account
    > Checks if user account already exists, terminates script if found
    > Creates new user per specified parameters
    > Checks if local Administrator is disabled, disables if not (if parameter defined)

*  CREATED: 23-07-22 | TawTek
*  UPDATED: 23-08-13 | TawTek
*  VERSION: 3.0

*  CHANGELOG:

    > 23-07-22  Developed first iteration of script
    > 23-08-05  Added check for local Administrator account and disable if active
                Reorganized variables into $NewUserParams to utilize splatting for better organization
                Added PasswordNeverExpires parameter to $NewUserParams
                Segregated script into functions for modularity
    > 23-08-13  Added $AdministratorDisabled parameter as a toggle for running Test-Administrator check
                Rearranged variables for cleaner error output and handling
**********************************************************************************************************
}
$VerbosePreference = "Continue"
$CheckUser = Get-LocalUser -Name $NewUser -ErrorAction SilentlyContinue

###---Writes script informational text to console---###
function Write-Info {
    Write-Host $Info
}

###---Checks if all parameters are defined and whether $NewUser exists and creates if not---###
function New-User {
    if ($NewUser -and $Group -and $Password){
        if ($CheckUser){
            Write-Verbose "$NewUser already exists, terminating script."
        } else {
            ###---Utilize splatting using parameters defined to create new local user---###
            $NewUserParams = @{'AccountNeverExpires' = $true;
                   'Password' = (ConvertTo-SecureString -AsPlainText -Force $Password);
                   'Name' = $NewUser;
                   'PasswordNeverExpires' = $true}
            New-LocalUser @NewUserParams -ErrorAction Stop | Add-LocalGroupMember -Group $Group -ErrorAction Stop
            Write-Verbose "$NewUser account has been created belonging to the $Group group with password set as $Password"
        }
    } else {
        Write-Verbose "All parameters must be defined: enter Username, User Group, and Password when executing script."
        exit
    }
}

###---Checks if local Administrator account is disabled and disables if not---###
function Test-Administrator {
    if ($AdministratorDisabled -eq $True){
        Write-Verbose "Checking if local Administrator account is disabled."
        if ((get-localuser 'Administrator').enabled) {
            Disable-LocalUser 'Administrator'
            Write-Verbose "Local Administrator account has been disabled."
        } else {
            Write-Verbose "Local Administrator account is already disabled."
        }
    } else {}
}

Write-Info
New-User
Test-Administrator