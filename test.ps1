Param(
    [Parameter(Mandatory = $true)]
    [String]
    $VMUsername,
    [Parameter(Mandatory = $true)]
    [String]
    $VMPassword,
    [Parameter(Mandatory = $true)]
    [String]
    $SubscriptionName,
    [Parameter(Mandatory = $true)]
    [String]
    $computername,
    [Parameter(Mandatory = $true)]
    [String]
    $PtrUserName,
    [Parameter(Mandatory = $true)]
    [String]
    $PtrPassword,
    [Parameter(Mandatory = $true)]
    [String]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [String]
    $DomainName,
    [Parameter(Mandatory = $true)]
    [String]
    $TenantId,
    [Parameter(Mandatory = $true)]
    [String]
    $Location,
    [Parameter(Mandatory = $true)]
    [String]
    $SQLUserName,
    [Parameter(Mandatory = $true)]
    [String]
    $SQLPassword
)

$vmsecurepass=ConvertTo-SecureString -String $VMPassword -asPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($VMUsername,$vmsecurepass)
$so = New-PsSessionOption –SkipCACheck -SkipCNCheck
$s = New-PSSession -ComputerName $computername -Credential $cred -UseSSL -SessionOption $so

Invoke-Command -Session $s -ScriptBlock {
 param($PtrUserName,$PtrPassword,$SubscriptionName,$ResourceGroupName,$DomainName,$TenantId,$Location,$SQLUserName,$SQLPassword)   
#sleep -Seconds 30
hostname
cd "C:\RDMISetup"
.\RDMI-Setup.ps1 -PtrUserName $PtrUserName -PtrPassword $PtrPassword -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName -DomainName $DomainName -TenantId $TenantId -Location $Location -SQLUserName $SQLUserName -SQLPassword $SQLPassword
} -ArgumentList ($PtrUserName,$PtrPassword,$SubscriptionName,$ResourceGroupName,$DomainName,$TenantId,$Location,$SQLUserName,$SQLPassword)

Remove-PSSession $s
