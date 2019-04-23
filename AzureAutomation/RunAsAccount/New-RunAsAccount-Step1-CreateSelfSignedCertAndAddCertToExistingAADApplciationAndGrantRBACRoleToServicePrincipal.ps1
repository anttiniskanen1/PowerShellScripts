#Requires -RunAsAdministrator
<#

.SYNOPSIS 
    Creates Azure Automation Run As account (Step1) for existing AAD Application.

.DESCRIPTION
   This script will execute the below operations to create Azure Automation Run As account (Step1)
     #0. Creates the self-signed certificate, (Optional step, if EnterpriseCertPathForRunAsAccount is not provided)
     #1. Add the cert to existing AAD Application,
     #2. Create ADServicePrincipal for the ApplicationId if not exist. If exist then check Contributor or Owner role already assigned to Service Principal.
     #3. Create new custom role definition "Automation RunAs Contributor" if not exist.
     #4. Grant "Automation RunAs Contributor" RBAC role to Service Principal ApplicationId if not assigned.

   Next step:
     Please take the ApplicationId and Certificate path from this script output to execute the Step2 script
     to complete the Azure Run As Account.
    'New-RunAsAccount-Step2-CreateAzureRunAsCertificateAndCreateAzureRunAsConnection.ps1'    

.EXAMPLE 
   .\New-RunAsAccount-Step1-CreateSelfSignedCertAndAddCertToExistingAADApplciationAndGrantRBACRoleToServicePrincipal.ps1 -SubscriptionId <SubscriptionId> -ApplicationId <ApplicationId> -SelfSignedCertPlainPassword <StrongPassword>

.NOTES

    AUTHOR: Azure/OMS Automation Team
    LASTEDIT: Apr 22, 2018  

#>
Param (

    [Parameter(Mandatory = $true)]
    [String] $ApplicationId,

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

function CreateSelfSignedCertificate([string] $certificateName, [string] $selfSignedCertPlainPassword, [string] $certPath, [string] $selfSignedCertNoOfMonthsUntilExpired) {
    $cert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation cert:\LocalMachine\My `
        -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -NotAfter (Get-Date).AddMonths($selfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256

    $CertPassword = ConvertTo-SecureString $selfSignedCertPlainPassword -AsPlainText -Force
    Export-PfxCertificate -Cert ("Cert:\localmachine\my\" + $cert.Thumbprint) -FilePath $certPath -Password $CertPassword -Force | Write-Verbose
}

function GetAADApplicationAndAddCert([System.Security.Cryptography.X509Certificates.X509Certificate2] $PfxCert, [string] $applicationId) {
    # Find the application
    $Filter = "AppId eq '" + $applicationId + "'"
    $Application = Get-AzureADApplication -Filter $Filter 

    if (!$Application)
    {
       Write-Host -ForegroundColor red  "Error : ApplicationId " $applicationId "not found."
       exit 1
    }
    # Requires Application administrator or GLOBAL ADMIN
    # Add new certificate to application
    New-AzureADApplicationKeyCredential -ObjectId $Application.ObjectId -CustomKeyIdentifier ([System.Convert]::ToBase64String($PfxCert.GetCertHash())) `
         -Type AsymmetricX509Cert -Usage Verify -Value ([System.Convert]::ToBase64String($PfxCert.GetRawCertData())) -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter | Write-Verbose    
}

function CreateADServicePrincipalOrCheckContributorOwnerRoleAssignedToServicePrincipal([string] $applicationId, [string] $subscriptionId) {
    $GetServicePrincipal = Get-AzureRmADServicePrincipal -ApplicationId $applicationId
    if (!$GetServicePrincipal) {
      # Requires Application administrator or GLOBAL ADMIN
      $ServicePrincipal = New-AzureRMADServicePrincipal -ApplicationId $applicationId 
      $GetServicePrincipal = Get-AzureRmADServicePrincipal -ObjectId $ServicePrincipal.Id
    } else {
      # if the ServicePrincipal exist then check whether Owner or Contributor role assigned already and print warning
      $subscriptionScope = "/subscriptions/" + $SubscriptionId
      $getContributorRoleAssigned = Get-AzureRMRoleAssignment `
                                      -ServicePrincipalName $applicationId `
                                      -RoleDefinitionName "Contributor" `
                                      -Scope $subscriptionScope `
                                      -ErrorAction SilentlyContinue
      if ($getContributorRoleAssigned) 
      {
         Write-Host -ForegroundColor yellow  "Warning : Contributor RBAC role is already assigned to Service Principal ApplicationId " $applicationId ". This may cause security issue. Please review and remove the Contributor role assignment."
      }

      $getOwnerRoleAssigned = Get-AzureRMRoleAssignment `
                                -ServicePrincipalName $applicationId `
                                -RoleDefinitionName "Owner" `
                                -Scope $subscriptionScope `
                                -ErrorAction SilentlyContinue
      if ($getOwnerRoleAssigned) 
      {
         Write-Host -ForegroundColor yellow  "Warning : Owner RBAC role is already assigned to Service Principal ApplicationId " $applicationId ". This may cause security issue. Please review and remove the Owner role assignment."
      }
    }
}

function CreateNewCustomRoleDefinition([string] $newRoleName, [string] $subscriptionId) {
    # Retrieve the existing "Contributor" role definition
    $builtinRoleDefinition = Get-AzureRmRoleDefinition -Name Contributor -ErrorAction Stop

    Write-Host
    # Create a new role definition for everything except Key Vault
    $newRoleDefinition = Get-AzureRmRoleDefinition -Name $newRoleName
    if ($newRoleDefinition) 
    {
        Write-Host -ForegroundColor green "New Role definition '$NewRoleName' already exists"
    } 
    else 
    {
        Write-Host -ForegroundColor yellow "New Role definition '$NewRoleName' will be created"
        $AutomationRunAsContributor = $builtinRoleDefinition
        $AutomationRunAsContributor.IsCustom = $true
        $AutomationRunAsContributor.Name = $newRoleName
        $AutomationRunAsContributor.Description = "Can manage all resources except Key Vault and access permissions"
        $AutomationRunAsContributor.Id = $null
        $AutomationRunAsContributor.NotActions.Add("Microsoft.KeyVault/*")
        $AutomationRunAsContributor.AssignableScopes.Clear()
        $newAssignableScope = "/subscriptions/" + $subscriptionId
        $AutomationRunAsContributor.AssignableScopes.Add($newAssignableScope)

        $newRoleDefinition = New-AzureRMRoleDefinition -Role $AutomationRunAsContributor -ErrorAction Stop 
        Write-Host -ForegroundColor green "New Role definition '$NewRoleName' created"
    }

    return $newRoleDefinition
}

function GrantRBACRoleToApplicationId([string] $applicationId, [string] $subscriptionId, [string] $newRoleName) {
  $subscriptionScope = "/subscriptions/" + $SubscriptionId
  $getNewRoleAssigned = Get-AzureRMRoleAssignment `
                          -ServicePrincipalName $applicationId `
                          -RoleDefinitionName $newRoleName `
                          -Scope $subscriptionScope `
                          -ErrorAction Stop
  if ($getNewRoleAssigned) 
  {
    Write-Host -ForegroundColor green  "RBAC role '$newRoleName' already assigned to Service Principal ApplicationId"
  } else {
    New-AzureRmRoleAssignment -RoleDefinitionName $newRoleName -ServicePrincipalName $applicationId -ErrorAction Stop
  }
}

# Main code starting here ...
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
$connectAD = Connect-AzureAD -TenantId $tenantId -AccountId $accountId -AzureEnvironmentName $EnvironmentName 

# Create a Run As account by using a service principal
$CertifcateAssetName = "AzureRunAsCertificate"
$ConnectionAssetName = "AzureRunAsConnection"
$ConnectionTypeName = "AzureServicePrincipal"

if ($EnterpriseCertPathForRunAsAccount -and $EnterpriseCertPlainPasswordForRunAsAccount) {
    $PfxCertPathForRunAsAccount = $EnterpriseCertPathForRunAsAccount
    $PfxCertPlainPasswordForRunAsAccount = $EnterpriseCertPlainPasswordForRunAsAccount
}
else {
    $CertificateName = $CertifcateAssetName + "_" +$ApplicationId 
    $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
    $PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
    
    # #0: Creates the self-signed certificate, (Optional step, if EnterpriseCertPathForRunAsAccount is not provided)
    CreateSelfSignedCertificate $CertificateName $PfxCertPlainPasswordForRunAsAccount $PfxCertPathForRunAsAccount $SelfSignedCertNoOfMonthsUntilExpired
}

# #1: Add the cert to exisitng ADD Applciation
$PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
GetAADApplicationAndAddCert -PfxCert  $PfxCert -ApplicationId $ApplicationId

# #2: Create ADServicePrincipal for the ApplicationId if not exist. If exist then check Contributor or Owner role already assigned to Service Principal.
CreateADServicePrincipalOrCheckContributorOwnerRoleAssignedToServicePrincipal -ApplicationId $ApplicationId -subscriptionId $SubscriptionId

# #3. Create new custom role definition "Automation RunAs Contributor" if not exist.
$NewRoleName = "Automation RunAs Contributor"
$createdNewRoleDefinition = CreateNewCustomRoleDefinition -newRoleName $NewRoleName -subscriptionId $SubscriptionId

# #4. Grant "Automation RunAs Contributor" RBAC role to Service Principal ApplicationId if not assigned
GrantRBACRoleToApplicationId -ApplicationId $ApplicationId -subscriptionId $SubscriptionId -newRoleName $NewRoleName

Write-Host
Write-Host -ForegroundColor green  "Completed the Step1 script"
Write-Host -ForegroundColor green  "========================== "
Write-Host -ForegroundColor green  "  ApplicationId is " $ApplicationId
Write-Host -ForegroundColor green  "  Certificate path is "$PfxCertPathForRunAsAccount
Write-Host -ForegroundColor yellow "  Next step : Please take the above ApplciationId, Certificate path and execute the Step2 script 'New-RunAsAccount-Step2-CreateAzureRunAsCertificateAndCreateAzureRunAsConnection.ps1' to complete the Azure Run As Account."
Write-Host