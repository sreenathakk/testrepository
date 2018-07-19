Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $SubscriptionId,
    [Parameter(Mandatory=$True)]
    [String] $Username,
    [Parameter(Mandatory=$True)]
    [string] $Password,
     [Parameter(Mandatory=$True)]
    [string] $resourceGroupName
 
)


$LoadModule=Get-Module -ListAvailable "Azure*"
if(!$LoadModule){
Install-PackageProvider NuGet -Force
Install-Module -Name AzureRM.profile -AllowClobber -Force
Install-Module -Name AzureRM.resources -AllowClobber -Force
Install-Module -Name AzureRM.Compute -AllowClobber -Force
}
Import-Module AzureRM.profile
Import-Module AzureRM.resources
Import-Module AzureRM.Compute

        try{
        $Securepass=ConvertTo-SecureString -String $Password -AsPlainText -Force
        $Azurecred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList($Username, $Securepass)
        $login=Login-AzureRmAccount -Credential $Azurecred -SubscriptionId $SubscriptionId
        Remove-AzureRmResourceGroup -Name $resourceGroupName -Force
                       
        }
        catch{
        Write-Error $_.Exception.Message
        }