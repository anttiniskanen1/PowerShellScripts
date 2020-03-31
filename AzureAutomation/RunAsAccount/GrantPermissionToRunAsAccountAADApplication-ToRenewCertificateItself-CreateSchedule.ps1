<#
.SYNOPSIS
    This script will grant the required permission to Azure Automation Run As Account AAD Application to 
    renew the ceritifcate itself and create a schedule for monthly/weekly renewal.
    
.MODULES REQUIRED (PREREQUISITES)
     This script uses the below modules
         Az.Accounts
         Az.Automation
         Az.Resources
         AzureAD

     Please use the below command to install the modules (if the modules are not in the local computer)
         Install-Module -Name Az.Accounts
         Install-Module -Name Az.Automation
         Install-Module -Name Az.Resources
         Install-Module -Name AzureAD

.DESCRIPTION
    This script will grant the required permission to Azure Automation Run As Account AAD Application to renew the ceritifcate itself.

    A. You need to be an Global Administrator / Company Administrator in Azure AD to be able to execute this script.
        Related Doc : https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles#available-roles

    B. This Power Shell script is doing the following operations
         1) Get the Run As Account AAD ApplicationId from automation connection asset "AzureRunAsConnection".
         2) Grant Owner permission to RunAsAccount AAD Service Principal for RunAsAccount AAD Application.
         3) Assign the "Application.ReadWrite.OwnedBy" App Role to the RunAsAccount AAD Service Principal.
         4) Import Update Azure Modules runbook from github open source and Start Update Azure Modules
            (Related link : https://raw.githubusercontent.com/Microsoft/AzureAutomation-Account-Modules-Update/master/Update-AutomationAzureModulesForAccount.ps1)
         5) Import UpdateAutomationRunAsCredential runbook
            (Related link : https://raw.githubusercontent.com/azureautomation/runbooks/master/Utility/ARM/Update-AutomationRunAsCredential.ps1 )
         6) Create a weekly or monthly schedule for UpdateAutomationRunAsCredential runbook
         7) Start the UpdateAutomationRunAsCredential onetime
   
.USAGE
    .\GrantPermissionToRunAsAccountAADApplication-ToRenewCertificateItself-CreateSchedule.ps1 -ResourceGroup <ResourceGroupName> `
            -AutomationAccountName <NameofAutomationAccount> `
            -SubscriptionId <SubscriptionId> 

.NOTES
    AUTHOR: Automation Team
    LASTEDIT: Mar 10th 2019
#>
Param (
    [Parameter(Mandatory = $true)]
    [String] $ResourceGroup,

    [Parameter(Mandatory = $true)]
    [String] $AutomationAccountName,

    [Parameter(Mandatory = $true)]
    [String] $SubscriptionId,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Monthly", "Weekly")]
    [string]$ScheduleRenewalInterval = "Weekly",

    [Parameter(Mandatory = $false)]
    [ValidateSet("AzureCloud", "AzureUSGovernment", "AzureChinaCloud")]
    [string]$EnvironmentName = "AzureCloud"
)
$message = "This script will`n"
$message = $message + "1) Grant Owner permission to Automation RunAsAccount AAD Service Principal for RunAsAccount AAD Application.`n"
$message = $message + "2) Assign the 'Application.ReadWrite.OwnedBy' App Role to the RunAsAccount AAD Service Principal.`n"
$message = $message + "Do you want To Proceed? (Y/N):"
$confirmation = Read-Host $message 
if ($confirmation -ieq 'N') {
  EXIT(1)
}
Import-Module Az.Accounts
Import-Module Az.Automation
Import-Module Az.Resources
Import-Module AzureAD
Connect-AzAccount
Select-AzSubscription -SubscriptionId $SubscriptionId | Out-Null

$currentAzureContext = Get-AzContext
$tenantId = $currentAzureContext.Tenant.Id
$accountId = $currentAzureContext.Account.Id
Connect-AzureAD -TenantId $tenantId -AccountId $accountId

Get-AzAutomationAccount -ResourceGroupName $ResourceGroup -Name $AutomationAccountName | Out-Null

# Step 1: Get the Run As Account AAD ApplicationId from automation connectionAsset "AzureRunAsConnection"
$connectionAssetName = "AzureRunAsConnection"
$runasAccountConnection = Get-AzAutomationConnection -Name $connectionAssetName `
                          -ResourceGroupName $ResourceGroup  -AutomationAccountName $AutomationAccountName
[GUID]$runasAccountAADAplicationId=$runasAccountConnection.FieldDefinitionValues['ApplicationId']

$runasAccountAADAplication = Get-AzADApplication -ApplicationId $runasAccountAADAplicationId
$runasAccountAADservicePrincipal = Get-AzureADServicePrincipal -Filter "AppId eq '$runasAccountAADAplicationId'"

# Step 2: Grant Owner permission to RunAsAccount AAD Service Principal for RunAsAccount AAD Application
Add-AzureADApplicationOwner -ObjectId $runasAccountAADAplication.ObjectId `
 -RefObjectId $runasAccountAADservicePrincipal.ObjectId | Out-Null

# Get the Service Principal for the Azure AD Graph
# App ID of AAD Graph:
$AADGraphAppId = "00000002-0000-0000-c000-000000000000"
$graphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$AADGraphAppId'"
# On the Graph Service Principal, find the App Role "Application.ReadWrite.OwnedBy" 
# that has the permission to update the Application
$permissionName = "Application.ReadWrite.OwnedBy"
$appRole = $graphServicePrincipal.appRoles | Where-Object {$_.Value -eq $permissionName -and $_.AllowedMemberTypes -contains "Application"}
# Step 3: Assign the "Application.ReadWrite.OwnedBy" App Role to the RunAsAccount AAD Service Principal.
New-AzureAdServiceappRoleAssignment `
  -ObjectId $runasAccountAADservicePrincipal.ObjectId `
  -PrincipalId $runasAccountAADservicePrincipal.ObjectId `
  -ResourceId $graphServicePrincipal.ObjectId -Id $appRole.Id | Out-Null

# Step 4: Import Update Azure Modules runbook from github open source and Start Update Azure Modules
$updateAzureModulesForAccountRunbookName = "Update-AutomationAzureModulesForAccount"
$updateAzureModulesForAccountRunbookPath = Join-Path (Get-PSDrive -Name Temp).Root ($updateAzureModulesForAccountRunbookName+".ps1")
Invoke-WebRequest -Uri https://raw.githubusercontent.com/Microsoft/AzureAutomation-Account-Modules-Update/master/Update-AutomationAzureModulesForAccount.ps1 `
     -OutFile $updateAzureModulesForAccountRunbookPath
Import-AzAutomationRunbook -ResourceGroupName $ResourceGroup `
  -AutomationAccountName $AutomationAccountName `
  -Path $updateAzureModulesForAccountRunbookPath -Type PowerShell | Out-Null
Publish-AzAutomationRunbook `
   -Name $updateAzureModulesForAccountRunbookName `
   -ResourceGroupName $ResourceGroup `
   -AutomationAccountName $AutomationAccountName | Out-Null
$runbookParameters = @{"AUTOMATIONACCOUNTNAME"=$AutomationAccountName;"RESOURCEGROUPNAME"=$ResourceGroup; "AZUREENVIRONMENT"=$EnvironmentName}
$updateModulesJob = Start-AzAutomationRunbook -Name $updateAzureModulesForAccountRunbookName `
  -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -Parameters $runbookParameters

# Step 5: Import UpdateAutomationRunAsCredential runbook
$UpdateAutomationRunAsCredentialRunbookName = "Update-AutomationRunAsCredential"
$UpdateAutomationRunAsCredentialRunbookPath = Join-Path (Get-PSDrive -Name Temp).Root ($UpdateAutomationRunAsCredentialRunbookName+".ps1")
Invoke-WebRequest -Uri https://raw.githubusercontent.com/azureautomation/runbooks/master/Utility/ARM/Update-AutomationRunAsCredential.ps1 `
    -OutFile $UpdateAutomationRunAsCredentialRunbookPath
Import-AzAutomationRunbook -ResourceGroupName $ResourceGroup `
    -AutomationAccountName $AutomationAccountName `
    -Path $UpdateAutomationRunAsCredentialRunbookPath -Type PowerShell | Out-Null
Publish-AzAutomationRunbook `
    -Name $UpdateAutomationRunAsCredentialRunbookName `
    -ResourceGroupName $ResourceGroup `
    -AutomationAccountName $AutomationAccountName | Out-Null

# Step 6: Create a weekly or monthly schedule for UpdateAutomationRunAsCredential runbook
$scheduleName="UpdateAutomationRunAsCredentialSchedule"
$todayDate = get-date -Hour 0 -Minute 00 -Second 00
$startDate = $todayDate.AddDays(1)
#Create a Schedule to run $UpdateAutomationRunAsCredentialRunbookName monthly
if ($ScheduleRenewalInterval -eq "Monthly") 
{
  $scheduleName = $scheduleName + $ScheduleRenewalInterval
  New-AzAutomationSchedule –AutomationAccountName $AutomationAccountName `
               –Name $scheduleName  -ResourceGroupName $ResourceGroup  `
               -StartTime $startDate -MonthInterval 1 `
               -DaysOfMonth One | Out-Null
} 
elseif ($ScheduleRenewalInterval -eq "Weekly") 
{
  $scheduleName = $scheduleName + $ScheduleRenewalInterval  
  New-AzAutomationSchedule –AutomationAccountName $AutomationAccountName `
               –Name $scheduleName  -ResourceGroupName $ResourceGroup `
               -StartTime $startDate -DaysOfWeek Sunday `
               -WeekInterval 1  | Out-Null
}
Register-AzAutomationScheduledRunbook –AutomationAccountName $AutomationAccountName `
 -ResourceGroupName $ResourceGroup -ScheduleName $scheduleName `
 -RunbookName $UpdateAutomationRunAsCredentialRunbookName | Out-Null

# Step 7: Start the UpdateAutomationRunAsCredential onetime
$seconds = 30
do {
   $updateModulesJob = Get-AzAutomationJob -Id $updateModulesJob.JobId -ResourceGroupName $ResourceGroup `
                         -AutomationAccountName $AutomationAccountName
   Write-Output ("Updating Azure Modules for automation account. Job Status is " + $updateModulesJob.Status + ". Sleeping for " + $seconds + " seconds...")
   Start-Sleep -Seconds $seconds
} while ($updateModulesJob.Status -ne "Completed" -and $updateModulesJob.Status -ne "Failed" -and $updateModulesJob.Status -ne "Suspended")

if ($updateModulesJob.Status -eq "Completed")
{
  Write-Output ("Updated Azure Modules for " + $AutomationAccountName)
  $updateAutomationRunAsCredentialJob = Start-AzAutomationRunbook `
    -Name $UpdateAutomationRunAsCredentialRunbookName `
    -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName
  $message = "Process Automation Job started for automation account.`n"
  $message = $message + "Please check the Azure Portal (Automation Accounts - " + $AutomationAccountName + " - Jobs) for job status of Runbook " + $UpdateAutomationRunAsCredentialRunbookName + " with jobid " + $updateAutomationRunAsCredentialJob.JobId.ToString()
  Write-Host -ForegroundColor green $message
} 
else
{
   $message = "Updated Azure Modules job completed with status " + $updateModulesJob.Status + ". Please debug the issue."
   Write-Host -ForegroundColor red $message
}