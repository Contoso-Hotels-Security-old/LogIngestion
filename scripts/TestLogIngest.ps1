param (
	[Parameter(Mandatory=$false)]
	[string]$SamplePath = 'https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample Data/CEF/AkamaiSIEM.csv',
	[Parameter(Mandatory=$false)]
	[string]$Format = 'csv',
	[Parameter(Mandatory=$false)]
	[string]$targetTableName = 'CommonSecurityLog',
	[Parameter(Mandatory=$false)]
	[string]$Replacements = '{ }',
    [Parameter(Mandatory=$false)]
	[string]$timestampColumn = "",
	[Parameter(Mandatory=$false)]
	[string]$startdate = '',
	[Parameter(Mandatory=$false)]
	[bool]$Test = $true
)

$VerbosePreference = 'SilentlyContinue'

Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity
$AzureContext = (Connect-AzAccount -Identity).context
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext

$sample = (Invoke-WebRequest -Uri $SamplePath -UseBasicParsing).Content
$sampleData = if($Format -eq 'json') {$sample |ConvertFrom-Json} else {$sample |ConvertFrom-Csv}

if($sampleData[0].psObject.Properties.name -notcontains "TimeGenerated") {
    $constantdate = (Get-Date).addhours(-5)
    foreach($row in $sampleData)
    {   
        if (!$timestampColumn) {
            $constantdate = $constantdate.AddSeconds($(Get-Random -Minimum 10 -Maximum 30))
            $row | Add-Member -MemberType NoteProperty -Name "TimeGenerated" -Value $constantdate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        }else {
            $row | Add-Member -MemberType NoteProperty -Name "TimeGenerated" -Value $row.$timestampColumn
        }

    }
}

if ($targetTableName -like 'Custom-*' -and (($sampleData[0] -match "/") -or ($sampleData[0] -match " "))){
    foreach($row in $sampleData)
    {
        foreach ($item in $row.psObject.Properties) {
            if ($item.name -match '/'){
                $ItemValue = $item.value
                $row.psObject.Properties.Remove($item.name)
                $row | Add-Member -MemberType NoteProperty -Name "$($item.Name.replace('/','_'))" -Value $ItemValue
            }elseif ($item.name -match ' '){
                $ItemValue = $item.value
                $row.psObject.Properties.Remove($item.name)
                $row | Add-Member -MemberType NoteProperty -Name "$($item.Name.replace(' ','_'))" -Value $ItemValue
            }
        }
    }
}

#write-output $Replacements
if ($Replacements.StartsWith("'") -and $Replacements.endswith("'") ) {
	$Replacements = $Replacements.Trim("'")
	$Replacements = $Replacements.Replace("\n", "")
	$Replacements = $Replacements.Replace("\","")
	$ReplacementsObj = $Replacements|ConvertFrom-Json
}else {
	$ReplacementsObj = $Replacements|ConvertFrom-Json
}

[string[]] $formats = @('M/d/yyyy, h:mm:ss.fff tt', 'yyyy-MM-ddTHH:mm:ss.fffZ', 'yyyy-MM-ddTHH:mm:ss.ffZ', 'yyyy-MM-ddTHH:mm:ss.fZ', 'yyyy-MM-ddTHH:mm:ssZ', 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-ddTHH:mm:ss')

$now = Get-Date

$row = $sampleData[0]
$fields = $row.psObject.Properties.Name
[ref]$date = [DateTime]::MinValue
$timestampFields = @()
foreach ($field in $fields) {
  Write-Host "Field name = " $field
  if ($null -ne $row.$field) {
    if (($row.$field.GetType().name -ne "PSCustomObject") -and ([DateTime]::TryParseExact($row.$field, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $date))){
      $timestampFields += $field
    }
  }  
}
#$timestampFields = @($fields|? {[DateTime]::TryParseExact($row.$_, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $date)})
#$timestampFields = @($fields|? {($row.$_.GetType().name -ne "PSCustomObject") -and ([DateTime]::TryParseExact($row.$_, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $date))})
$tsField = $timestampFields[0]
$alldates = $sampleData.$tsField |
%{
    [ref]$rowDate = [DateTime]::MinValue
    [DateTime]::TryParseExact($_, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $rowDate) | Out-Null
    $rowDate.Value
}
$FirstDate = $alldates | Sort-Object | Select-Object -First 1
$lastDate = $alldates | Sort-Object | Select-Object -Last 1

#$tsField = $timestampFields[0]
foreach($row in $sampleData)
{

    [ref]$date = Get-Date  
    
    $dateStr = $row.$tsField 

    [DateTime]::TryParseExact($dateStr, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $date) | Out-Null
   
    #$shift = ($lastDate - $date.Value).TotalSeconds
    
    #$newDate = $now.AddSeconds(-$shift)
	if ($startdate) {
		$shift = ($FirstDate - $date.Value).TotalSeconds
        $result = New-Object DateTime
        [DateTime]::TryParseExact($startdate, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$result) | Out-Null
        $newDate = $result.AddSeconds(-$shift)
    }else {
		$shift = ($lastDate - $date.Value).TotalSeconds
        $newDate = $now.AddSeconds(-$shift)
    }
    
    foreach($df in $fields|?{$_ -like "*``[*``]*"})
    {
        $newName = $df -replace '\s?\[.*\]', ''
        $value = $row.$df
        $row.PSObject.Properties.Remove($df)
        $row| Add-Member -MemberType NoteProperty -Name $newName -Value $value
        if($timestampFields -eq $df)
        {
            $timestampFields = $timestampFields -ne $df
            if(!($timestampFields -eq $newName))
            {
                $timestampFields += $newName
            }
        }
    }

    foreach($df in $timestampFields)
    {
        $row.$df = $newDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }

    
    foreach($replacementField in $ReplacementsObj.PSObject.Properties.Name)
    {
        foreach($replacement in $ReplacementsObj.$replacementField)
        {
            if(($row.$replacementField -eq $replacement.value) -or ($row.$replacementField -match $replacement.value))
            {
                $row.$replacementField = $replacement.replacement
            }
        }
    }

    $row.PSObject.Properties.Remove('_ResourceId')
    $row.PSObject.Properties.Remove('TenantId')
    $row.PSObject.Properties.Remove('MG')
}

$logData = $sampleData| Sort-Object -Property TimeGenerated | ConvertTo-Json

if($Test)
{	
	if ($($($logData | ConvertFrom-Json).GetType()).basetype.name -eq "Object") {
        $logData = "[$logData]"
    }
    Write-Output $logData
}

