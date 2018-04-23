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
