param (
	[Parameter(Mandatory=$false)]
	[string]$SamplePath = 'https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample Data/CEF/AkamaiSIEM.csv',
	[Parameter(Mandatory=$false)]
	[string]$Format = 'csv',
	[Parameter(Mandatory=$false)]
	[string]$targetTableName = 'CommonSecurityLog',
	[Parameter(Mandatory=$false)]
    [string]$existedDCRLink = "",
	[Parameter(Mandatory=$false)]
	[string]$Replacements = '{
    "SourceIP": [
      {
        "value": "1.2.3.4",
        "replacement": "192.168.1.1"
      },
      {
        "value": "10.10.10.11",
        "replacement": "192.168.1.2"
      }
    ]
  }',
	[Parameter(Mandatory=$false)]
	[string]$Recurring = '1 hour'
)

Disable-AzContextAutosave -Scope Process

# Connect to Azure with system-assigned managed identity
$AzureContext = (Connect-AzAccount -Identity).context

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext

$StartTime = (Get-Date).AddMinutes(10)
$automationAccountName = Get-AutomationVariable -Name "AAName"
$automationAccountRG = Get-AutomationVariable -Name "AARG"

$ScheduleName = $targetTableName.Split('-')[0] +'-'+ ($SamplePath.Split('/')[-1]).Split('.')[0]

if (Get-AzAutomationSchedule -AutomationAccountName $automationAccountName -Name "$ScheduleName" -ResourceGroupName $automationAccountRG -ErrorAction SilentlyContinue){
	write-output "The schedule for this type of logs and for this file already exists"

}else{
	if ($Recurring -match "hour") {
		[int]$interval = $Recurring.Split(" ")[0]
		New-AzAutomationSchedule -AutomationAccountName $automationAccountName -Name "$ScheduleName" -StartTime $StartTime -HourInterval $interval -ResourceGroupName $automationAccountRG
	}elseif ($Recurring -eq "Daily") {
		New-AzAutomationSchedule -AutomationAccountName $automationAccountName -Name "$ScheduleName" -StartTime $StartTime -DayInterval 1 -ResourceGroupName $automationAccountRG
	}elseif ($Recurring -eq "Weekly") {
		New-AzAutomationSchedule -AutomationAccountName $automationAccountName -Name "$ScheduleName" -StartTime $StartTime -WeekInterval 1 -ResourceGroupName $automationAccountRG
	}
	$params = @{"SamplePath"="$SamplePath"; "Format"="$Format"; "targetTableName"="$targetTableName";"Replacements"="$Replacements"; "existedDCRLink"="$existedDCRLink"; "Test" = $false}
    Register-AzAutomationScheduledRunbook -AutomationAccountName $automationAccountName `
    	-Name "CommonLogIngest" -ScheduleName "$ScheduleName" -Parameters $params `
        -ResourceGroupName $automationAccountRG
}
