[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Validate', 'Deploy', 'Replay', 'All', 'Verify')]
    [string]$Action = 'Menu',
    [string]$Scenario = 'All',
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [string]$RunId,
    [string]$PrincipalId,
    [ValidateSet('User', 'ServicePrincipal')]
    [string]$PrincipalType = 'User',
    [switch]$ForceDeploy,
    [ValidateRange(0, 60)]
    [int]$WaitMinutes = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or newer is required.' }
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration file not found: $ConfigPath" }
$script:config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
foreach ($key in @('subscriptionId', 'tenantId', 'resourceGroup', 'workspaceName', 'workspaceCustomerId', 'dceName')) {
    if ([string]::IsNullOrWhiteSpace([string]$config[$key])) { throw "Missing config.json value: $key" }
}
foreach ($key in @('subscriptionId', 'tenantId', 'workspaceCustomerId')) {
    $parsedId = [guid]::Empty
    if (-not [guid]::TryParse([string]$config[$key], [ref]$parsedId)) { throw "config.json value $key must be a GUID." }
}
foreach ($key in @('user', 'workstation', 'server', 'cluster', 'mfaAttackIp', 'riskyAttackIp', 'patAttackIp', 'redactedLegitimateIp', 'mailSink')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.entities[$key])) { throw "Missing config.json entity: $key" }
}
foreach ($key in @('mfaAttackIp', 'riskyAttackIp', 'patAttackIp', 'redactedLegitimateIp')) {
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$config.entities[$key], [ref]$parsedIp)) { throw "config.json entity $key must be an IP address." }
}
foreach ($ip in @($config.blockedLocalIps)) {
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$ip, [ref]$parsedIp)) { throw 'config.json blockedLocalIps contains an invalid IP address.' }
    if (@($config.entities.Values) -contains [string]$ip) { throw 'A blocked local IP is also configured as a replay entity.' }
}
$script:workspaceId = "/subscriptions/$($config.subscriptionId)/resourceGroups/$($config.resourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($config.workspaceName)"
$script:dceId = "/subscriptions/$($config.subscriptionId)/resourceGroups/$($config.resourceGroup)/providers/Microsoft.Insights/dataCollectionEndpoints/$($config.dceName)"

function Invoke-AzJson {
    param([string[]]$Arguments)
    $output = & az @Arguments --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Azure CLI failed: $($output | Out-String)" }
    return ($output | Out-String | ConvertFrom-Json -Depth 50)
}

function Get-AzureToken {
    param([string]$Resource)
    $token = & az account get-access-token --subscription $config.subscriptionId --resource $Resource --query accessToken -o tsv --only-show-errors
    if ($LASTEXITCODE -ne 0 -or -not $token) { throw "Could not obtain an Azure token for $Resource" }
    return ($token | Select-Object -First 1).Trim()
}

function Assert-AzureTarget {
    $account = Invoke-AzJson @('account', 'show', '-o', 'json')
    if ($account.id -ne $config.subscriptionId -or $account.tenantId -ne $config.tenantId) {
        throw 'Azure CLI subscription or tenant differs from config.json. No Azure writes were attempted.'
    }
    $workspace = Invoke-AzJson @('monitor', 'log-analytics', 'workspace', 'show', '-g', $config.resourceGroup, '-n', $config.workspaceName, '-o', 'json')
    if ($workspace.id -ine $workspaceId -or $workspace.customerId -ne $config.workspaceCustomerId) {
        throw 'Existing workspace ID or customer ID differs from config.json. No Azure writes were attempted.'
    }
    return $workspace
}

function Get-Packs {
    $packs = @(
        Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'scenarios') -Directory | ForEach-Object {
            $manifestPath = Join-Path $_.FullName 'manifest.json'
            if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return }
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
            [pscustomobject]@{ Id = [string]$manifest.id; Directory = $_.FullName; Manifest = $manifest }
        }
    )
    if ($packs.Count -eq 0) { throw 'No scenario packs were found.' }
    if (@($packs.Id | Select-Object -Unique).Count -ne $packs.Count) { throw 'Scenario IDs must be unique.' }
    if (@($packs.Manifest.tableName | Select-Object -Unique).Count -ne $packs.Count) { throw 'Scenario table names must be unique.' }
    if (@($packs.Manifest.ruleId | Select-Object -Unique).Count -ne $packs.Count) { throw 'Scenario rule IDs must be unique.' }
    return @($packs | Sort-Object @{ Expression = { $_.Manifest.group } }, @{ Expression = { $_.Manifest.name } })
}

function Resolve-SelectedPacks {
    param([object[]]$Packs, [string]$Selection)
    $tokens = @($Selection -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($tokens.Count -eq 0) { throw 'Select at least one analytics rule.' }
    $selected = [System.Collections.Generic.List[object]]::new()
    foreach ($token in $tokens) {
        if ($token -ieq 'All') {
            foreach ($pack in $Packs) { $selected.Add($pack) }
            continue
        }
        if ($token -match '^(\d+)-(\d+)$') {
            $first = [int]$Matches[1]
            $last = [int]$Matches[2]
            if ($first -lt 1 -or $last -gt $Packs.Count -or $first -gt $last) { throw "Invalid rule range: $token" }
            for ($i = $first; $i -le $last; $i++) { $selected.Add($Packs[$i - 1]) }
            continue
        }
        if ($token -match '^\d+$') {
            $index = [int]$token
            if ($index -lt 1 -or $index -gt $Packs.Count) { throw "Rule number is out of range: $token" }
            $selected.Add($Packs[$index - 1])
            continue
        }
        $matches = @($Packs | Where-Object { $_.Id -ieq $token -or $_.Manifest.group -ieq $token })
        if ($matches.Count -eq 0) { throw "Unknown analytics rule or group: $token" }
        foreach ($pack in $matches) { $selected.Add($pack) }
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    return @($selected | Where-Object { $seen.Add($_.Id) })
}

function Get-PackQuery {
    param($Pack)
    if ($Pack.Manifest.queryFile) {
        return (Get-Content -LiteralPath (Get-PackFile $Pack 'queryFile') -Raw).Trim()
    }
    $aggregates = [System.Collections.Generic.List[string]]::new()
    $conditions = [System.Collections.Generic.List[string]]::new()
    $index = 0
    foreach ($stage in @($Pack.Manifest.requiredStages.Keys | Sort-Object)) {
        if ($stage -cnotmatch '^[A-Z][A-Z0-9_]{1,63}$') { throw "$($Pack.Id): invalid stage name $stage." }
        $index++
        $aggregates.Add("Stage$($index)Count=countif(Stage == '$stage')")
        $conditions.Add("Stage$($index)Count >= $([int]$Pack.Manifest.requiredStages[$stage])")
    }
    if ($aggregates.Count -eq 0) { throw "$($Pack.Id): requiredStages must not be empty." }
    $table = [string]$Pack.Manifest.tableName
    $scenarioId = $Pack.Id
    $summary = $aggregates -join ', '
    $predicate = $conditions -join ' and '
    return @"
$table
| where TimeGenerated > ago(1h) and ingestion_time() > ago(20m)
| where IsSynthetic == true and Scenario == '$scenarioId'
| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated), Events=count(), Stages=make_set(Stage), $summary, Actor=take_any(Actor), Host=take_any(Host), SourceIp=take_any(SourceIp) by RunId
| where $predicate
| project TimeGenerated=EndTime, StartTime, EndTime, RunId, Events, Stages, Actor, Host, SourceIp
"@
}

function Get-PackFile {
    param($Pack, [string]$Name)
    $relative = [string]$Pack.Manifest[$Name]
    if ([string]::IsNullOrWhiteSpace($relative) -or [System.IO.Path]::IsPathRooted($relative)) { throw "$($Pack.Id): invalid $Name path." }
    $path = [System.IO.Path]::GetFullPath((Join-Path $Pack.Directory $relative))
    $prefix = [System.IO.Path]::GetFullPath($Pack.Directory).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$($Pack.Id): $Name must be a file inside its scenario folder."
    }
    return $path
}

function Expand-EntityTokens {
    param([string]$Value)
    foreach ($key in $config.entities.Keys) {
        $Value = $Value.Replace("{{$key}}", [string]$config.entities[$key])
    }
    if ($Value -match '\{\{[^{}]+\}\}') { throw "Unknown entity token in evidence: $Value" }
    return $Value
}

function New-Events {
    param($Pack, [string]$CurrentRunId)
    $path = Get-PackFile $Pack 'evidenceFile'
    $source = @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 30 | Sort-Object ObservedAt)
    if ($source.Count -eq 0) { throw "$($Pack.Id): evidence file is empty." }
    $events = [System.Collections.Generic.List[object]]::new()
    $now = [datetime]::UtcNow
    for ($i = 0; $i -lt $source.Count; $i++) {
        $row = $source[$i]
        if ($row.Scenario -ne $Pack.Id -or $row.IsSynthetic -ne $true -or -not $row.Stage -or -not $row.SourceTable) {
            throw "$($Pack.Id): evidence row $i is incomplete or not marked synthetic."
        }
        $minutesAgo = 14 - (13.0 * $i / [math]::Max(1, $source.Count - 1))
        $events.Add([pscustomobject][ordered]@{
            TimeGenerated = $now.AddMinutes(-$minutesAgo).ToString('o')
            Scenario = $Pack.Id
            RunId = $CurrentRunId
            Stage = [string]$row.Stage
            SourceTable = [string]$row.SourceTable
            Operation = [string]$row.Operation
            Actor = Expand-EntityTokens ([string]$row.Actor)
            Host = Expand-EntityTokens ([string]$row.Host)
            SourceIp = Expand-EntityTokens ([string]$row.SourceIp)
            Target = Expand-EntityTokens ([string]$row.Target)
            Details = Expand-EntityTokens ([string]$row.Details)
            IsSynthetic = $true
        })
    }
    foreach ($stage in $Pack.Manifest.requiredStages.Keys) {
        $actual = @($events | Where-Object Stage -EQ $stage).Count
        $minimum = [int]$Pack.Manifest.requiredStages[$stage]
        if ($minimum -lt 1 -or $actual -lt $minimum) {
            throw "$($Pack.Id): $stage has $actual rows but requires $minimum."
        }
    }
    $serialized = ConvertTo-Json -InputObject $events.ToArray() -Depth 20 -Compress
    foreach ($ip in @($config.blockedLocalIps)) {
        if ($serialized.Contains([string]$ip)) { throw "$($Pack.Id): a blocked local IP appears in the replay payload. No ingestion was attempted." }
    }
    return $events.ToArray()
}

function Assert-Pack {
    param($Pack)
    $m = $Pack.Manifest
    if ($Pack.Id -notmatch '^[A-Za-z][A-Za-z0-9]{0,19}$') { throw "Invalid scenario ID: $($Pack.Id)" }
    if ([string]$m.group -notin @('S1', 'S2', 'S3')) { throw "$($Pack.Id): group must be S1, S2, or S3." }
    if ([string]$m.tableName -cnotmatch '^[A-Za-z][A-Za-z0-9_]*_CL$') { throw "$($Pack.Id): invalid custom table name." }
    $guid = [guid]::Empty
    if (-not [guid]::TryParse([string]$m.ruleId, [ref]$guid)) { throw "$($Pack.Id): invalid rule ID." }
    if ([string]::IsNullOrWhiteSpace([string]$m.name) -or [string]::IsNullOrWhiteSpace([string]$m.description)) {
        throw "$($Pack.Id): name and description are required."
    }
    if ([string]$m.severity -notin @('High', 'Medium', 'Low', 'Informational')) { throw "$($Pack.Id): invalid severity." }
    $query = (Get-PackQuery $Pack).Trim()
    if (-not $query.StartsWith([string]$m.tableName + "`n") -and -not $query.StartsWith([string]$m.tableName + "`r`n")) {
        throw "$($Pack.Id): detection query must start with its own table name."
    }
    if ($query -notmatch '\bRunId\b' -or $query -notmatch 'IsSynthetic') {
        throw "$($Pack.Id): detection must filter synthetic rows and group by RunId."
    }
    foreach ($stage in $m.requiredStages.Keys) {
        if (-not $query.Contains("'$stage'")) { throw "$($Pack.Id): detection query does not mention required stage $stage." }
    }
    $events = @(New-Events $Pack ([guid]::NewGuid().ToString()))
    Write-Output "$($Pack.Id): $($m.name) | $($m.tableName) | $($events.Count) rows | $($m.requiredStages.Count) required stages"
}

function Get-Resource {
    param([string]$Id, [string]$ApiVersion, [switch]$AllowMissing)
    $token = Get-AzureToken 'https://management.azure.com/'
    $response = Invoke-WebRequest -Method Get -Uri "https://management.azure.com$Id`?api-version=$ApiVersion" -Headers @{ Authorization = "Bearer $token" } -SkipHttpErrorCheck
    if ([int]$response.StatusCode -eq 404 -and $AllowMissing) { return $null }
    if ([int]$response.StatusCode -ne 200) { throw "ARM GET failed with HTTP $($response.StatusCode): $Id" }
    return ($response.Content | ConvertFrom-Json -Depth 50)
}

function Get-PackResourceIds {
    param($Pack)
    $id = $Pack.Id.ToLowerInvariant()
    return @{
        Table = "$workspaceId/tables/$($Pack.Manifest.tableName)"
        Dcr = "/subscriptions/$($config.subscriptionId)/resourceGroups/$($config.resourceGroup)/providers/Microsoft.Insights/dataCollectionRules/sentinel-incident-lab-$id-dcr"
        Rule = "$workspaceId/providers/Microsoft.SecurityInsights/alertRules/$($Pack.Manifest.ruleId)"
    }
}

function Test-PackDeployment {
    param($Pack)
    $ids = Get-PackResourceIds $Pack
    return [bool]((Get-Resource $dceId '2022-06-01' -AllowMissing) -and
        (Get-Resource $ids.Table '2023-09-01' -AllowMissing) -and
        (Get-Resource $ids.Dcr '2024-03-11' -AllowMissing) -and
        (Get-Resource $ids.Rule '2024-03-01' -AllowMissing))
}

function Invoke-BicepDeployment {
    param([string]$Template, [string]$Name, [hashtable]$Values)
    $parameters = @{}
    foreach ($key in $Values.Keys) { $parameters[$key] = @{ value = $Values[$key] } }
    $document = @{ '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'; contentVersion = '1.0.0.0'; parameters = $parameters }
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) "incident-lab-$([guid]::NewGuid()).parameters.json"
    try {
        [System.IO.File]::WriteAllText($temp, ($document | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
        $deployment = Invoke-AzJson @('deployment', 'group', 'create', '-g', $config.resourceGroup, '--name', $Name, '--template-file', (Join-Path $PSScriptRoot $Template), '--parameters', "@$temp", '-o', 'json')
        if ($deployment.properties.provisioningState -ne 'Succeeded') { throw "Deployment $Name did not succeed." }
    } finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
}

function Wait-ForTable {
    param($Pack)
    for ($attempt = 1; $attempt -le 40; $attempt++) {
        try {
            $null = Invoke-AzJson @('monitor', 'log-analytics', 'query', '--subscription', $config.subscriptionId, '--workspace', $config.workspaceCustomerId, '--analytics-query', "$($Pack.Manifest.tableName) | count", '--timespan', 'P1D', '-o', 'json')
            return
        } catch {
            if ($attempt -eq 40) { throw "$($Pack.Id): table did not become queryable within 10 minutes." }
            Start-Sleep -Seconds 15
        }
    }
}

function Deploy-Packs {
    param([object[]]$Packs, $Workspace)
    if (-not $PrincipalId) {
        if ($PrincipalType -eq 'ServicePrincipal') { throw 'Pass -PrincipalId for a service principal.' }
        $principal = Invoke-AzJson @('ad', 'signed-in-user', 'show', '-o', 'json')
        $script:PrincipalId = [string]$principal.id
    }
    if (-not (Get-Resource $dceId '2022-06-01' -AllowMissing) -or $ForceDeploy) {
        Invoke-BicepDeployment 'base.bicep' 'sentinel-incident-lab-base' @{ location = $Workspace.location; dceName = $config.dceName }
        Write-Output "Shared endpoint deployed: $($config.dceName)"
    }
    foreach ($pack in $Packs) {
        if ((Test-PackDeployment $pack) -and -not $ForceDeploy) {
            Write-Output "$($pack.Id): existing table, DCR and rule found; skipping deployment."
            continue
        }
        $m = $pack.Manifest
        $query = (Get-PackQuery $pack).Trim()
        $values = @{
            workspaceName = $config.workspaceName
            location = $Workspace.location
            dceName = $config.dceName
            scenarioId = $pack.Id
            tableName = $m.tableName
            ruleId = $m.ruleId
            ruleDisplayName = [string]$m.name
            ruleDescription = [string]$m.description
            severity = $m.severity
            query = $query
            ingestorPrincipalId = $PrincipalId
            ingestorPrincipalType = $PrincipalType
        }
        $values.deployRule = $false
        Invoke-BicepDeployment 'scenario.bicep' "incident-lab-$($pack.Id.ToLowerInvariant())-table" $values
        Wait-ForTable $pack
        $values.deployRule = $true
        Invoke-BicepDeployment 'scenario.bicep' "incident-lab-$($pack.Id.ToLowerInvariant())-rule" $values
        Write-Output "$($pack.Id): table, DCR, RBAC and stable Sentinel rule deployed."
    }
}

function Submit-Pack {
    param($Pack, [string]$CurrentRunId)
    if (-not (Test-PackDeployment $Pack)) { throw "$($Pack.Id): deployment is missing. Use -Action All or Deploy first." }
    $ids = Get-PackResourceIds $Pack
    $dcr = Get-Resource $ids.Dcr '2024-03-11'
    $dce = Get-Resource $dceId '2022-06-01'
    $endpoint = [string]$dce.properties.logsIngestion.endpoint
    if (-not $endpoint -or -not $dcr.properties.immutableId) { throw "$($Pack.Id): ingestion endpoint or DCR immutable ID is missing." }
    $stream = "Custom-$($Pack.Manifest.tableName)"
    $uri = "$($endpoint.TrimEnd('/'))/dataCollectionRules/$($dcr.properties.immutableId)/streams/$stream`?api-version=2023-01-01"
    $events = @(New-Events $Pack $CurrentRunId)
    $body = ConvertTo-Json -InputObject $events -Depth 20 -Compress
    $token = Get-AzureToken 'https://monitor.azure.com/'
    for ($attempt = 1; $attempt -le 8; $attempt++) {
        try {
            $response = Invoke-WebRequest -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body
            if ([int]$response.StatusCode -ne 204) { throw "Unexpected ingestion status: $($response.StatusCode)" }
            Write-Output "$($Pack.Id): submitted $($events.Count) synthetic rows to $($Pack.Manifest.tableName)."
            return
        } catch {
            $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            if ($attempt -eq 8 -or $status -ne 403) { throw }
            Start-Sleep -Seconds 30
        }
    }
}

function Assert-ReplayWindow {
    param([object[]]$Packs)
    foreach ($pack in $Packs) {
        $query = "$($pack.Manifest.tableName) | where IsSynthetic == true and ingestion_time() > ago(20m) | summarize RecentRuns=dcount(RunId)"
        $rows = @(Invoke-AzJson @('monitor', 'log-analytics', 'query', '--subscription', $config.subscriptionId, '--workspace', $config.workspaceCustomerId, '--analytics-query', $query, '--timespan', 'P1D', '-o', 'json'))
        if ($rows.Count -gt 0 -and [int]$rows[0].RecentRuns -gt 0) {
            throw "$($pack.Id): a recent replay is still inside the rule's 20-minute suppression window. Wait before ingesting again. No new rows were sent."
        }
    }
}

function Get-LogCount {
    param($Pack, [string]$CurrentRunId)
    $query = "$($Pack.Manifest.tableName) | where RunId == '$CurrentRunId' and IsSynthetic == true | summarize Rows=count()"
    $rows = @(Invoke-AzJson @('monitor', 'log-analytics', 'query', '--subscription', $config.subscriptionId, '--workspace', $config.workspaceCustomerId, '--analytics-query', $query, '--timespan', 'P1D', '-o', 'json'))
    if ($rows.Count -eq 0) { return 0 }
    return [int]$rows[0].Rows
}

function Get-Incidents {
    param([string]$CurrentRunId)
    $token = Get-AzureToken 'https://management.azure.com/'
    $uri = "https://management.azure.com$workspaceId/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01"
    $found = @()
    while ($uri) {
        $page = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $token" }
        $found += @($page.value | Where-Object { $_.properties.title -like "*$CurrentRunId*" })
        $uri = if ($page.PSObject.Properties.Name -contains 'nextLink') { $page.nextLink } else { $null }
    }
    return $found
}

function Wait-ForResults {
    param([object[]]$Packs, [string]$CurrentRunId)
    $deadline = [datetime]::UtcNow.AddMinutes($WaitMinutes)
    do {
        $incidents = @(Get-Incidents $CurrentRunId)
        $complete = $true
        foreach ($pack in $Packs) {
            $expected = @(New-Events $pack $CurrentRunId).Count
            $actual = Get-LogCount $pack $CurrentRunId
            $matches = @($incidents | Where-Object { $_.properties.title -like "$($pack.Manifest.name) - $CurrentRunId*" })
            Write-Output "$($pack.Id): $actual/$expected rows; $($matches.Count) incident(s)."
            if ($actual -lt $expected -or $matches.Count -eq 0) { $complete = $false }
            foreach ($incident in $matches) {
                Write-Output "  Incident #$($incident.properties.incidentNumber): https://portal.azure.com/#resource$($incident.id)"
            }
            if ($matches.Count -gt 1) { Write-Warning "$($pack.Id): duplicate incidents for run $CurrentRunId." }
        }
        if ($complete) { return }
        if ([datetime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Seconds 30
    } while ($true)
    Write-Warning "Run $CurrentRunId did not have all expected logs and incidents within $WaitMinutes minutes. Check ingestion and analytics rule health."
}

function Invoke-LabAction {
    param([string]$SelectedAction, [string]$SelectedScenario)
    $packs = @(Get-Packs)
    $selected = @(Resolve-SelectedPacks $packs $SelectedScenario)
    foreach ($pack in $selected) { Assert-Pack $pack }
    if ($SelectedAction -eq 'Validate') {
        foreach ($pack in $selected) {
            $ids = Get-PackResourceIds $pack
            Write-Output "Rule: $($pack.Manifest.name) | $($ids.Rule)"
            Write-Output "DCR: $($ids.Dcr)"
            Write-Output "Detection KQL:`n$((Get-PackQuery $pack).Trim())"
        }
        Write-Output 'Validation complete. No Azure calls or writes were made.'
        return
    }
    if ($SelectedAction -eq 'Verify' -and -not $RunId) { throw 'Provide -RunId to verify an earlier run.' }
    if ($SelectedAction -ne 'Verify' -and $RunId) { throw '-RunId is only accepted with -Action Verify.' }
    if ($SelectedAction -eq 'Verify') {
        $parsedRunId = [guid]::Empty
        if (-not [guid]::TryParse($RunId, [ref]$parsedRunId)) { throw 'RunId must be a GUID.' }
        $script:RunId = $parsedRunId.ToString()
    }
    $workspace = Assert-AzureTarget
    if ($SelectedAction -in @('Deploy', 'All')) {
        Deploy-Packs $selected $workspace
        if ($SelectedAction -eq 'Deploy') { return }
    }
    if ($SelectedAction -eq 'Verify') {
        Wait-ForResults $selected $RunId
        return
    }
    Assert-ReplayWindow $selected
    $currentRunId = [guid]::NewGuid().ToString()
    Write-Output "RunId: $currentRunId"
    foreach ($pack in $selected) { Submit-Pack $pack $currentRunId }
    foreach ($pack in $selected) {
        Write-Output "KQL: $($pack.Manifest.tableName) | where RunId == '$currentRunId' | order by TimeGenerated asc"
    }
    if ($WaitMinutes -gt 0) { Wait-ForResults $selected $currentRunId }
}

if ($Action -ne 'Menu') {
    Invoke-LabAction $Action $Scenario
    return
}

while ($true) {
    $packs = @(Get-Packs)
    Write-Host "`nSentinel Forge - synthetic replay" -ForegroundColor Cyan
    for ($i = 0; $i -lt $packs.Count; $i++) {
        Write-Host "  $($i + 1). $($packs[$i].Manifest.name)"
        Write-Host "     $($packs[$i].Manifest.description)" -ForegroundColor DarkGray
    }
    Write-Host '  Enter numbers, ranges, IDs or groups (for example 1,3-5 or S1,S3).'
    Write-Host '  Enter All for every rule.'
    Write-Host '  0. Exit'
    $choice = Read-Host 'Analytics rules'
    if ($choice -eq '0') { break }
    try { $selectedPacks = @(Resolve-SelectedPacks $packs $choice) } catch { Write-Warning $_.Exception.Message; continue }
    $selectedId = ($selectedPacks.Id -join ',')
    while ($true) {
        Write-Host "`nSelected: $selectedId" -ForegroundColor Cyan
        Write-Host '  1. Preview and validate (offline)'
        Write-Host '  2. Deploy only'
        Write-Host '  3. Replay only (deployment must exist)'
        Write-Host '  4. Deploy and replay'
        Write-Host '  5. Verify an earlier RunId'
        Write-Host '  0. Back'
        $mode = Read-Host 'Action'
        if ($mode -eq '0') { break }
        $selectedAction = switch ($mode) { '1' { 'Validate' }; '2' { 'Deploy' }; '3' { 'Replay' }; '4' { 'All' }; '5' { 'Verify' }; default { $null } }
        if (-not $selectedAction) { continue }
        $script:RunId = if ($selectedAction -eq 'Verify') { Read-Host 'RunId' } else { $null }
        if ($selectedAction -eq 'Deploy') {
            $answer = Read-Host 'This deploys Azure ingestion resources and enabled Sentinel rules. Continue? [y/N]'
            if ($answer -notin @('y', 'Y', 'yes', 'YES')) { continue }
        }
        if ($selectedAction -in @('Replay', 'All')) {
            $answer = Read-Host 'This ingests billable synthetic logs and may create Sentinel incidents. Continue? [y/N]'
            if ($answer -notin @('y', 'Y', 'yes', 'YES')) { continue }
        }
        try { Invoke-LabAction $selectedAction $selectedId } catch { Write-Error $_.Exception.Message -ErrorAction Continue }
    }
}
