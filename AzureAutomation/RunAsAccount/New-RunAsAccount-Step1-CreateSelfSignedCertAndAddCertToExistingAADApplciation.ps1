#Requires -RunAsAdministrator
<#

.SYNOPSIS 
   Creates the self-signed certificate and add the cert to existing AAD Application for 
   Azure Automation Run As account(Step1)


.DESCRIPTION
   Creates the self-signed certificate and add the cert to existing AAD Application for 
   Azure Automation Run As account(Step1)

   Next step:
   Please take the ApplicationId and Certificate path from this script output to execute the Step2 script
   to complete the Azure Run As Account.
   'New-RunAsAccount-Step2-CreateAzureRunAsCertificateAndCreateAzureRunAsConnection.ps1'    

.EXAMPLE 
   .\New-RunAsAccount-Step1-CreateSelfSignedCertAndAddCertToExistingAADApplciation.ps1 -SubscriptionId <SubscriptionId> -AADApplicationId <AADApplicationId> -SelfSignedCertPlainPassword <StrongPassword>

.NOTES

    AUTHOR: Azure/OMS Automation Team
    LASTEDIT: Apr 19, 2018  

#>
Param (

    [Parameter(Mandatory = $true)]
    [String] $AADApplicationId,

    [Parameter(Mandatory = $true)]
    [String] $SubscriptionId,

    [Parameter(Mandatory = $true)]
    [String] $SelfSignedCertPlainPassword,

    [Parameter(Mandatory = $false)]
    [string] $EnterpriseCertPathForRunAsAccount,

    [Parameter(Mandatory = $false)]
    [String] $EnterpriseCertPlainPasswordForRunAsAccount,

    [Parameter(Mandatory = $false)]
    [ValidateSet("AzureCloud", "AzureUSGovernment")]
    [string]$EnvironmentName = "AzureCloud",

    [Parameter(Mandatory = $false)]
    [int] $SelfSignedCertNoOfMonthsUntilExpired = 12
)

function CreateSelfSignedCertificate([string] $certificateName, [string] $selfSignedCertPlainPassword,
    [string] $certPath, [string] $selfSignedCertNoOfMonthsUntilExpired) {
    $cert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation cert:\LocalMachine\My `
        -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -NotAfter (Get-Date).AddMonths($selfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256

    $CertPassword = ConvertTo-SecureString $selfSignedCertPlainPassword -AsPlainText -Force
    Export-PfxCertificate -Cert ("Cert:\localmachine\my\" + $cert.Thumbprint) -FilePath $certPath -Password $CertPassword -Force | Write-Verbose
}

function GetAADApplicationAndAddCert([System.Security.Cryptography.X509Certificates.X509Certificate2] $PfxCert, [string] $ApplicationId) {
    # Find the application
    $Filter = "AppId eq '" + $ApplicationId + "'"
    $Application = Get-AzureADApplication -Filter $Filter 

    if (!$Application)
    {
       Write-Host -ForegroundColor red  "Error : Application Id " $ApplicationId "not found."
       exit 1
    }
    # Requires Application administrator or GLOBAL ADMIN
    # Add new certificate to application
    New-AzureADApplicationKeyCredential -ObjectId $Application.ObjectId -CustomKeyIdentifier ([System.Convert]::ToBase64String($PfxCert.GetCertHash())) `
         -Type AsymmetricX509Cert -Usage Verify -Value ([System.Convert]::ToBase64String($PfxCert.GetRawCertData())) -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter | Write-Verbose    
}

function CreateADServicePrincipal([string] $ApplicationId) {
    # Requires Application administrator or GLOBAL ADMIN
    $GetServicePrincipal = Get-AzureRmADServicePrincipal -ApplicationId $ApplicationId
    if (!$GetServicePrincipal) {
      $ServicePrincipal = New-AzureRMADServicePrincipal -ApplicationId $ApplicationId 
      $GetServicePrincipal = Get-AzureRmADServicePrincipal -ObjectId $ServicePrincipal.Id
    }
}

Import-Module AzureRM.Profile
Import-Module AzureRM.Resources
Import-Module AzureAD

$AzureRMProfileVersion = (Get-Module AzureRM.Profile).Version
if (!(($AzureRMProfileVersion.Major -ge 3 -and $AzureRMProfileVersion.Minor -ge 4) -or ($AzureRMProfileVersion.Major -gt 3))) {
    Write-Error -Message "Please install the latest Azure PowerShell and retry. Relevant doc url : https://docs.microsoft.com/powershell/azureps-cmdlets-docs/ "
    return
}

Connect-AzureRmAccount -Environment $EnvironmentName 
$Subscription = Select-AzureRmSubscription -SubscriptionId $SubscriptionId

$currentAzureContext = Get-AzureRmContext
$tenantId = $currentAzureContext.Tenant.Id
$accountId = $currentAzureContext.Account.Id
Connect-AzureAD -TenantId $tenantId -AccountId $accountId -AzureEnvironmentName $EnvironmentName 

# Create a Run As account by using a service principal
$CertifcateAssetName = "AzureRunAsCertificate"
$ConnectionAssetName = "AzureRunAsConnection"
$ConnectionTypeName = "AzureServicePrincipal"

if ($EnterpriseCertPathForRunAsAccount -and $EnterpriseCertPlainPasswordForRunAsAccount) {
    $PfxCertPathForRunAsAccount = $EnterpriseCertPathForRunAsAccount
    $PfxCertPlainPasswordForRunAsAccount = $EnterpriseCertPlainPasswordForRunAsAccount
}
else {
    $CertificateName = $CertifcateAssetName + "_" +$AADApplicationId 
    $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
    $PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword

    CreateSelfSignedCertificate $CertificateName $PfxCertPlainPasswordForRunAsAccount $PfxCertPathForRunAsAccount $SelfSignedCertNoOfMonthsUntilExpired
}

# Add the cert to exisitng ADD Applciation
$PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
GetAADApplicationAndAddCert -PfxCert  $PfxCert -ApplicationId $AADApplicationId

# Create CreateADServicePrincipal for the ApplicationId if not exist
CreateADServicePrincipal -ApplicationId $AADApplicationId

Write-Host -ForegroundColor green  "Application Id is " $AADApplicationId
Write-Host -ForegroundColor green  "Certificate path is "$PfxCertPathForRunAsAccount
Write-Host -ForegroundColor yellow "Next step : Please take the above Applciation Id and Certificate path and execute the Step2 script 'New-RunAsAccount-Step2-CreateAzureRunAsCertificateAndCreateAzureRunAsConnection.ps1' to complete the Azure Run As Account."