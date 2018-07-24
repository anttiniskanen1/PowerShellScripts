<#

.SYNOPSIS 
   Creates the Azure Autoamtion Run As account using the self-signed certificate created from Key Vault.


.DESCRIPTION
   Creates the Azure Autoamtion Run As account using the self-signed certificate created from Key Vault.
    
.EXAMPLE

   Create a Run As account and a Classic Run As account by using a self-signed certificate
   .\New-RunAsAccountUsingKeyVault.ps1 -ResourceGroup <ResourceGroupName> -AutomationAccountName <NameofAutomationAccount> -SubscriptionId <SubscriptionId> -ApplicationDisplayName <DisplayNameofAADApplication> -SelfSignedCertPlainPassword <StrongPassword> -KeyVaultName <KeyVaultName> -CreateClassicRunAsAccount $true


.NOTES
    AUTHOR: Azure/OMS Automation Team
    LASTEDIT: Jul 24, 2018  

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
    [Boolean] $CreateClassicRunAsAccount,

    [Parameter(Mandatory = $true)]
    [String] $KeyVaultName,

    [Parameter(Mandatory=$true)]
    [String] $SelfSignedCertPlainPassword,
 
    [Parameter(Mandatory=$false)]
    [String] $KeyVaultLocation='East US 2',

    [Parameter(Mandatory = $false)]
    [String] $EnterpriseCertPathForRunAsAccount,

    [Parameter(Mandatory = $false)]
    [String] $EnterpriseCertPlainPasswordForRunAsAccount,

    [Parameter(Mandatory = $false)]
    [String] $EnterpriseCertPathForClassicRunAsAccount,

    [Parameter(Mandatory = $false)]
    [String] $EnterpriseCertPlainPasswordForClassicRunAsAccount,

    [Parameter(Mandatory = $false)]
    [ValidateSet("AzureCloud", "AzureUSGovernment")]
    [string]$EnvironmentName = "AzureCloud",

    [Parameter(Mandatory = $false)]
    [int] $SelfSignedCertNoOfMonthsUntilExpired = 12
 )

function ValidateKeyVaultAndCreate([string] $keyVaultName, [string] $resourceGroup,  [string] $KeyVaultLocation) {
    $GetKeyVault=Get-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroup -ErrorAction SilentlyContinue
    if (!$GetKeyVault)
    {
      Write-Warning -Message "Key Vault $keyVaultName not found. Creating the Key Vault $keyVaultName"
      $keyValut=New-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroup -Location $keyVaultLocation
      if (!$keyValut) {
        Write-Error -Message "Key Vault $keyVaultName creation failed. Please fix and continue"
        return
      }
      $uri = New-Object System.Uri($keyValut.VaultUri, $true)
      $hostName = $uri.Host
      while ((Resolve-DnsName -Name $hostName -DnsOnly -ErrorAction SilentlyContinue) -eq $null)
      {
         Start-Sleep -s 15
         Write-Output "$hostName is not available, retrying in 15s"
      }
      Write-Host -ForegroundColor yellow "Note: This script will not delete the KeyVault created. If required, please delete the same manually."
    }
}

function CreateSelfSignedCertificate([string] $keyVaultName, [string] $certificateName, [string] $selfSignedCertPlainPassword,[string] $certPath, [string] $certPathCer, [string] $SelfSignedCertNoOfMonthsUntilExpired ) {
    $certSubjectName="cn="+$certificateName

    $Policy = New-AzureKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $certSubjectName  -IssuerName "Self" -ValidityInMonths $noOfMonthsUntilExpired -ReuseKeyOnRenewal
    $AddAzureKeyVaultCertificateStatus = Add-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName -CertificatePolicy $Policy 
  
    While($AddAzureKeyVaultCertificateStatus.Status -eq "inProgress")
    {
      Start-Sleep -s 10
      $AddAzureKeyVaultCertificateStatus = Get-AzureKeyVaultCertificateOperation -VaultName $keyVaultName -Name $certificateName
    }
 
    if($AddAzureKeyVaultCertificateStatus.Status -ne "completed")
    {
      Write-Error -Message "Key vault cert creation is not sucessfull and its status is: $status.Status" 
    }

    $secretRetrieved = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $certificateName
    $pfxBytes = [System.Convert]::FromBase64String($secretRetrieved.SecretValueText)
    $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $certCollection.Import($pfxBytes,$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
   
    #Export  the .pfx file 
    $protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $selfSignedCertPlainPassword)
    [System.IO.File]::WriteAllBytes($certPath, $protectedCertificateBytes)

    #Export the .cer file 
    $cert = Get-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName
    $certBytes = $cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes($certPathCer, $certBytes)

    # Delete the cert after downloading
    $RemoveAzureKeyVaultCertificateStatus = Remove-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName -PassThru -Force -ErrorAction SilentlyContinue -Confirm:$false
}

function CreateServicePrincipal([System.Security.Cryptography.X509Certificates.X509Certificate2] $PfxCert, [string] $applicationDisplayName) {  
    $keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
    $keyId = (New-Guid).Guid

    #Create an Azure AD application, AD App Credential, AD ServicePrincipal
    $Application = New-AzureRmADApplication -DisplayName $ApplicationDisplayName -HomePage ("http://" + $applicationDisplayName) -IdentifierUris ("http://" + $keyId) 
    $ApplicationCredential = New-AzureRmADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter
    $ServicePrincipal = New-AzureRMADServicePrincipal -ApplicationId $Application.ApplicationId 
    $GetServicePrincipal = Get-AzureRmADServicePrincipal -ObjectId $ServicePrincipal.Id

    # Sleep here for a few seconds to allow the service principal application to become active (ordinarily takes a few seconds)
    Sleep -s 15
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

function CreateAutomationCertificateAsset ([string] $resourceGroup, [string] $automationAccountName, [string] $certifcateAssetName, [string] $certPath, [string] $certPlainPassword, [Boolean] $Exportable) {
    $CertPassword = ConvertTo-SecureString $certPlainPassword -AsPlainText -Force   
    Remove-AzureRmAutomationCertificate -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Name $certifcateAssetName -ErrorAction SilentlyContinue
    New-AzureRmAutomationCertificate -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Path $certPath -Name $certifcateAssetName -Password $CertPassword -Exportable:$Exportable  | write-verbose
}

function CreateAutomationConnectionAsset ([string] $resourceGroup, [string] $automationAccountName, [string] $connectionAssetName, [string] $connectionTypeName, [System.Collections.Hashtable] $connectionFieldValues ) {
    Remove-AzureRmAutomationConnection -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue
    New-AzureRmAutomationConnection -ResourceGroupName $ResourceGroup -AutomationAccountName $automationAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues
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

# Create a Run As account by using a service principal
$CertifcateAssetName = "AzureRunAsCertificate"
$ConnectionAssetName = "AzureRunAsConnection"
$ConnectionTypeName = "AzureServicePrincipal"

if ($EnterpriseCertPathForRunAsAccount -and $EnterpriseCertPlainPasswordForRunAsAccount) {
    $PfxCertPathForRunAsAccount = $EnterpriseCertPathForRunAsAccount
    $PfxCertPlainPasswordForRunAsAccount = $EnterpriseCertPlainPasswordForRunAsAccount
} else {
    ValidateKeyVaultAndCreate $KeyVaultName $ResourceGroup $KeyVaultLocation
    $CertificateName = $AutomationAccountName + $CertifcateAssetName
    $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
    $PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
    $CerCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".cer")
    CreateSelfSignedCertificate $KeyVaultName $CertificateName $PfxCertPlainPasswordForRunAsAccount $PfxCertPathForRunAsAccount $CerCertPathForRunAsAccount $SelfSignedCertNoOfMonthsUntilExpired
}

# Create a service principal
$PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
$ApplicationId = CreateServicePrincipal $PfxCert $ApplicationDisplayName

# Create the Automation certificate asset
CreateAutomationCertificateAsset $ResourceGroup $AutomationAccountName $CertifcateAssetName $PfxCertPathForRunAsAccount $PfxCertPlainPasswordForRunAsAccount $true

# Populate the ConnectionFieldValues
$SubscriptionInfo = Get-AzureRmSubscription -SubscriptionId $SubscriptionId
$TenantID = $SubscriptionInfo | Select TenantId -First 1
$Thumbprint = $PfxCert.Thumbprint
$ConnectionFieldValues = @{"ApplicationId" = $ApplicationId; "TenantId" = $TenantID.TenantId; "CertificateThumbprint" = $Thumbprint; "SubscriptionId" = $SubscriptionId}

# Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
CreateAutomationConnectionAsset $ResourceGroup $AutomationAccountName $ConnectionAssetName $ConnectionTypeName $ConnectionFieldValues

if ($CreateClassicRunAsAccount) {
    # Create a Run As account by using a service principal
    $ClassicRunAsAccountCertifcateAssetName = "AzureClassicRunAsCertificate"
    $ClassicRunAsAccountConnectionAssetName = "AzureClassicRunAsConnection"
    $ClassicRunAsAccountConnectionTypeName = "AzureClassicCertificate "
    $UploadMessage = "Please upload the .cer format of #CERT# to the Management store by following the steps below." + [Environment]::NewLine +
    "Log in to the Microsoft Azure portal (https://portal.azure.com) and select Subscriptions -> Management Certificates." + [Environment]::NewLine +
    "Then click Upload and upload the .cer format of #CERT#"

    if ($EnterpriseCertPathForClassicRunAsAccount -and $EnterpriseCertPlainPasswordForClassicRunAsAccount ) {
        $PfxCertPathForClassicRunAsAccount = $EnterpriseCertPathForClassicRunAsAccount
        $PfxCertPlainPasswordForClassicRunAsAccount = $EnterpriseCertPlainPasswordForClassicRunAsAccount
        $UploadMessage = $UploadMessage.Replace("#CERT#", $PfxCertPathForClassicRunAsAccount)
    } else {
        $ClassicRunAsAccountCertificateName = $AutomationAccountName + $ClassicRunAsAccountCertifcateAssetName
        $PfxCertPathForClassicRunAsAccount = Join-Path $env:TEMP ($ClassicRunAsAccountCertificateName + ".pfx")
        $PfxCertPlainPasswordForClassicRunAsAccount = $SelfSignedCertPlainPassword
        $CerCertPathForClassicRunAsAccount = Join-Path $env:TEMP ($ClassicRunAsAccountCertificateName + ".cer")
        $UploadMessage = $UploadMessage.Replace("#CERT#", $CerCertPathForClassicRunAsAccount)
        CreateSelfSignedCertificate $KeyVaultName $ClassicRunAsAccountCertificateName $PfxCertPlainPasswordForClassicRunAsAccount $PfxCertPathForClassicRunAsAccount $CerCertPathForClassicRunAsAccount $NoOfMonthsUntilExpired
    }

    # Create the Automation certificate asset
    CreateAutomationCertificateAsset $ResourceGroup $AutomationAccountName $ClassicRunAsAccountCertifcateAssetName $PfxCertPathForClassicRunAsAccount $PfxCertPlainPasswordForClassicRunAsAccount $false

    # Populate the ConnectionFieldValues
    $SubscriptionName = $subscription.Subscription.Name
    $ClassicRunAsAccountConnectionFieldValues = @{"SubscriptionName" = $SubscriptionName; "SubscriptionId" = $SubscriptionId; "CertificateAssetName" = $ClassicRunAsAccountCertifcateAssetName}

    # Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
    CreateAutomationConnectionAsset $ResourceGroup $AutomationAccountName $ClassicRunAsAccountConnectionAssetName $ClassicRunAsAccountConnectionTypeName   $ClassicRunAsAccountConnectionFieldValues

    Write-Host -ForegroundColor red       $UploadMessage
}