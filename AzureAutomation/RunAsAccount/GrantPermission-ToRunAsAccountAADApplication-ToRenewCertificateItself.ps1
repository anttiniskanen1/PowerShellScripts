<#
.SYNOPSIS
    This script will grant the required permission to Azure Automation Run As Account AAD Application to renew the ceritifcate itself.
    
.MODULES REQUIRED (PREREQUISITES)
     This script uses the below modules
         AzureRM.Profile
         AzureRM.Automation
         AzureAD

     Please use the below command to install the modules (if the modules are not in the local computer)
         Install-Module -Name AzureRM.Profile
         Install-Module -Name AzureRM.Automation
         Install-Module -Name AzureAD

.DESCRIPTION
    This script will grant the required permission to Azure Automation Run As Account AAD Application to renew the ceritifcate itself.

    1. You need to be an Global Administrator / Company Administrator in Azure AD to be able to execute this script.
        Related Doc : https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles#available-roles

    2. This Power Shell script is doing the following operations
         a) Get the Run As Account AAD ApplicationId from automation connection asset "AzureRunAsConnection".
         b) Grant Owner to Run As Account AAD Service Principal.
         c) Assign the "Application.ReadWrite.OwnedBy" App Role to the Run As Account AAD Service Principal.

    3. This script need to executed only once

    4. Next script. To configure the Run As Account Renewal please use the below script
        https://github.com/azureautomation/runbooks/blob/master/Utility/ARM/Update-AutomationRunAsCredential.ps1
    
.USAGE
    .\GrantPermission-ToRunAsAccountAADApplication-ToRenewCertificateItself.ps1 -ResourceGroup <ResourceGroupName> -AutomationAccountName <NameofAutomationAccount> -SubscriptionId <SubscriptionId> 

.NOTES
    AUTHOR: Automation Team
    LASTEDIT: Mar 7th 2019
#>
Param (
    [Parameter(Mandatory = $true)]
    [String] $ResourceGroup,

    [Parameter(Mandatory = $true)]
    [String] $AutomationAccountName,

    [Parameter(Mandatory = $true)]
    [String] $SubscriptionId
)
Connect-AzureRmAccount
$Subscription = Select-AzureRmSubscription -SubscriptionId $SubscriptionId

$currentAzureContext = Get-AzureRmContext
$tenantId = $currentAzureContext.Tenant.Id
$accountId = $currentAzureContext.Account.Id
Connect-AzureAD -TenantId $tenantId -AccountId $accountId

$automationAccount = Get-AzureRMAutomationAccount -ResourceGroupName $ResourceGroup -Name $AutomationAccountName

# Step 1:Get the Run As Account AAD ApplicationId from automation connectionAsset "AzureRunAsConnection"
$ConnectionAssetName = "AzureRunAsConnection"
$runasAccountConnection = Get-AzureRmAutomationConnection -Name $ConnectionAssetName -ResourceGroupName $ResourceGroup  -AutomationAccountName $AutomationAccountName
[GUID]$runasAccountAADAplicationId=$runasAccountConnection.FieldDefinitionValues['ApplicationId']

$runasAccountAADAplication = Get-AzureRmADApplication -ApplicationId $runasAccountAADAplicationId
$runasAccountAADservicePrincipal = Get-AzureADServicePrincipal -Filter "AppId eq '$runasAccountAADAplicationId'"

# Step 2: Grant Owner to Run As Account AAD Service Principal
Add-AzureADApplicationOwner -ObjectId $runasAccountAADAplication.ObjectId -RefObjectId $runasAccountAADservicePrincipal.ObjectId

# Step 3:  Get the Service Principal for the Microsoft Graph or Azure AD Graph, depending on what you want to call
# App ID of MS Graph:
$MSGraphAppId = "00000003-0000-0000-c000-000000000000"
# App ID of AAD Graph:
$AADGraphAppId = "00000002-0000-0000-c000-000000000000"

$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$AADGraphAppId'"

# Step 4:  On the Graph Service Principal, find the App Role "Application.ReadWrite.OwnedBy" that has the permission to update the Application
$PermissionName = "Application.ReadWrite.OwnedBy"
$AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}

# Step 5:  Assign the "Application.ReadWrite.OwnedBy" App Role to the Service Principal
# Note that you will get a generic "bad request, one or more properties are invalid" error if this app permission is already assigned
$AppRoleAssignment = New-AzureAdServiceAppRoleAssignment -ObjectId $runasAccountAADservicePrincipal.ObjectId -PrincipalId $runasAccountAADservicePrincipal.ObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $AppRole.Id