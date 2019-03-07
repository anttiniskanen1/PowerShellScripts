#Requires -RunAsAdministrator
<#
.SYNOPSIS
    This script can be used to create Azure Automation Run As Account using Power Shell and ARM Template.
    1) This script will create the AAD Application, AssignContributorRole 2) All other operations are in ARM Template.
    

.DESCRIPTION
    This script can be used to create Azure Automation Run As Account using Power Shell and ARM Template.

    Note: We need to create AAD Application first to configure Run As Account.
          AAD Application is not an ARM based resource or we do not have option to create AAD Application in ARM Template.
          So we cannot configure the entire runas account using an ARM template.

    1. This Power Shell script is doing the following operations
         a) Create the self-signed certificate 
         b) Create the AAD Application  
         c) AssignContributorRole to AAD Application at subscription level 
              (Role Assignment can be moved to ARM Template if the Role Assignment is done at Resource Group level. 
               In ARM Template we can grant Role Assignment only at Resource Group level and we cannot grant at subscription level.)
         d) Create TemplateParameterFile that can be used in New-AzureRMResourceGroupDeployment.
         e) ARM Template deployment using New-AzureRMResourceGroupDeployment to create the Automation account, Certificate and Connection Asset.

    2. All operations in the below script is done using Power Shell
       https://docs.microsoft.com/en-us/azure/automation/manage-runas-account#create-run-as-account-using-powershell
       
    3. The ARM Template is stored at
       https://raw.githubusercontent.com/ikanni/PowerShellScripts/master/AzureAutomation/RunAsAccount/ARMTemplates/NewRunAsAccount-ARMTemplate.JSON 
    
.USAGE
    .\New-RunAsAccount-UsingPowerShellAndARMTemplate.ps1 -ResourceGroup <ResourceGroupName> -AutomationAccountName <NameofAutomationAccount> -SubscriptionId <SubscriptionId> -ApplicationDisplayName <DisplayNameofAADApplication> -SelfSignedCertPlainPassword <StrongPassword>

.NOTES
    AUTHOR: Automation Team
    LASTEDIT: Mar 6th 2019
#>

Param (
    [Parameter(Mandatory = $true)]
    [String] $ResourceGroup,

    [Parameter(Mandatory = $true)]
    [String] $AutomationAccountName,

    [Parameter(Mandatory = $true)]
    [String] $ApplicationDisplayName,

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

function CreateSelfSignedCertificate(
  [string] $certificateName,
  [string] $selfSignedCertPlainPassword,
  [string] $certPath,
  [string] $selfSignedCertNoOfMonthsUntilExpired ) {
    $Cert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation cert:\LocalMachine\My `
        -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -NotAfter (Get-Date).AddMonths($selfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256

    $CertPassword = ConvertTo-SecureString $selfSignedCertPlainPassword -AsPlainText -Force
    Export-PfxCertificate -Cert ("Cert:\localmachine\my\" + $Cert.Thumbprint) -FilePath $certPath -Password $CertPassword -Force | Write-Verbose
}

function CreateServicePrincipalAndAssignContributorRole(
  [System.Security.Cryptography.X509Certificates.X509Certificate2] $PfxCert,
  [string] $applicationDisplayName) {  
    $keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
    $keyId = (New-Guid).Guid

    # Create an Azure AD application, AD App Credential, AD ServicePrincipal

    # Requires Application Developer Role, but works with Application administrator or GLOBAL ADMIN
    $Application = New-AzureRmADApplication -DisplayName $ApplicationDisplayName -HomePage ("http://" + $applicationDisplayName) -IdentifierUris ("http://" + $keyId) 
    # Requires Application administrator or GLOBAL ADMIN
    $ApplicationCredential = New-AzureRmADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter
    # Requires Application administrator or GLOBAL ADMIN
    $ServicePrincipal = New-AzureRMADServicePrincipal -ApplicationId $Application.ApplicationId 

    # Sleep here for a few seconds to allow the service principal application to become active (ordinarily takes a few seconds)
    Sleep -s 15
    # Requires User Access Administrator or Owner.
    $NewRole = New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
    $Retries = 0;
    While ($NewRole -eq $null -and $Retries -le 6) {
        Sleep -s 10
        New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId | Write-Verbose -ErrorAction SilentlyContinue
        $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
        $Retries++;
    }
    return $Application.ApplicationId.ToString();
}

function ConvertCertificateToBase64String([string] $FilePath, [string] $Password){
    # Set the required key storage flags
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable `
        -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet `
        -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($FilePath, $Password, $flags)

    # Export the certificate and convert into base 64 string
    $base64String = [System.Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12))
    return $base64String;
}

function GenerateParameterfile(
  [string] $automationAccountName,
  [string] $base64String,
  [string] $ApplicationId,
  [string] $Thumbprint, 
  [string] $parameterfileJsonPath){

  $script:AutomationAccountNameJson = [pscustomobject]@{
    value = $automationAccountName
  };

  $script:ApplicationIdJson = [pscustomobject]@{
    value = $ApplicationId
  };

  $script:ThumbprintJson = [pscustomobject]@{
    value = $Thumbprint
  };
  
  $script:Base64ValueJson = [pscustomobject]@{
    value = $base64String
  };
  
  $script:parameters = [pscustomobject]@{
    AutomationAccountName = $script:AutomationAccountNameJson;
    ApplicationId = $script:ApplicationIdJson;
    Thumbprint = $script:ThumbprintJson;
    Base64Value = $script:Base64ValueJson;
  };
  
  $script:parameterfile = [pscustomobject]@{
    '$schema' = 'https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#';
    contentVersion = '1.0.0.0';
    parameters = $script:parameters;
  };

  $parameterfileJson=$script:parameterfile | ConvertTo-Json;

  $parameterfileJson > $parameterfileJsonPath
}

Import-Module AzureRM.Profile
Import-Module AzureRM.Resources

$AzureRMProfileVersion = (Get-Module AzureRM.Profile).Version
if (!(($AzureRMProfileVersion.Major -ge 3 -and $AzureRMProfileVersion.Minor -ge 4) -or ($AzureRMProfileVersion.Major -gt 3))) {
    Write-Error -Message "Please install the latest Azure PowerShell and retry. Relevant doc url : https://docs.microsoft.com/powershell/azureps-cmdlets-docs/ "
    return
}

Connect-AzureRmAccount -Environment $EnvironmentName 
$Subscription = Select-AzureRmSubscription -SubscriptionId $SubscriptionId

if ($EnterpriseCertPathForRunAsAccount -and $EnterpriseCertPlainPasswordForRunAsAccount) {
    $PfxCertPathForRunAsAccount = $EnterpriseCertPathForRunAsAccount
    $PfxCertPlainPasswordForRunAsAccount = $EnterpriseCertPlainPasswordForRunAsAccount
}
else {
    $CertificateName = $AutomationAccountName + $CertifcateAssetName
    $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
    $PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
    #Create Self Signed Certificate
    CreateSelfSignedCertificate $CertificateName $PfxCertPlainPasswordForRunAsAccount $PfxCertPathForRunAsAccount $SelfSignedCertNoOfMonthsUntilExpired
}

# Get Cert Thumbprint & base64String
$PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
$Thumbprint = $PfxCert.Thumbprint
$base64String = ConvertCertificateToBase64String -FilePath $PfxCertPathForRunAsAccount -Password $PfxCertPlainPasswordForRunAsAccount

# Create a service principal and assign contributor role to AAD Application
$ApplicationId = CreateServicePrincipalAndAssignContributorRole $PfxCert $ApplicationDisplayName

# Generate ARMTemplate Parameter file
$parameterfileJsonPath= Join-Path $env:TEMP ($AutomationAccountName + ".param")
GenerateParameterfile -automationAccountName $AutomationAccountName -base64String $base64String -ApplicationId $ApplicationId -Thumbprint $Thumbprint -parameterfileJsonPath $parameterfileJsonPath

# ARM Template deployment to create the Automation account and Run As Account
New-AzureRMResourceGroupDeployment -ResourceGroupName $ResourceGroup `
  -TemplateUri https://raw.githubusercontent.com/ikanni/PowerShellScripts/master/AzureAutomation/RunAsAccount/ARMTemplates/NewRunAsAccount-ARMTemplate.JSON `
  -TemplateParameterFile $parameterfileJsonPath 