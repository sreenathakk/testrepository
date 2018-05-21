Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $AadTenantId,
    [Parameter(Mandatory=$True)]
    [String] $Username,
    [Parameter(Mandatory=$True)]
    [string] $Password,
    [Parameter(Mandatory=$True)]
    [string] $ResourceGroupName
 
)


$Securepass=ConvertTo-SecureString -String $Password -AsPlainText -Force
$Azurecred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList($Username, $Securepass)
Install-Module -Name AzureRM.Profile -AllowClobber -Force
Install-Module -Name AzureRM.Compute -AllowClobber -Force
Import-Module -Name AzureRM.Profile
Import-Module -Name AzureRM.Compute

$login=Login-AzureRmAccount -Credential $Azurecred -TenantId $AadTenantId

$ResourceGroup=Get-AzureRmResourceGroup -Name $ResourceGroupName
if($ResourceGroup){
Remove-AzureRmResourceGroup -Name $ResourceGroupName -Force
}
