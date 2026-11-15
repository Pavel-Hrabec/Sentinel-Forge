# Sentinel Forge

Sentinel Forge is a practical lab project connected to [Pavel Hrabec's AI Cybersecurity Academy](https://www.skool.com/ai-cybersecurity-academy/about). The community focuses on hands-on cybersecurity, SIEM, cloud, and AI skills. This tool gives learners repeatable Microsoft Sentinel investigations with evidence they can inspect and query.

Choose one or more of three bundled analytics rules from a PowerShell menu, replay explicitly synthetic records, and verify the resulting Microsoft Sentinel incidents. This is a standalone project. It does not create a Log Analytics workspace or impersonate native Entra, Exchange, Windows, DevOps, AKS, or Defender telemetry.

The design builds on the scenario-menu idea in [Sentinel LogSeeder OpenAI](https://github.com/Pavel-Hrabec/sentinel-logseeder-openai) and the original [Sentinel LogSeeder](https://github.com/javiersoriano/sentinel-logseeder). No Copilot or AI key is required for the bundled packs. This project has its own ingestion and deployment code.

## Where the telemetry comes from

The bundled evidence is derived from **observed logs produced during controlled attack simulations in a DEV environment** in November 2026. It includes sign-in/MFA, application consent, Exchange activity, Windows/Sysmon, DevOps PAT use, Azure activity, Key Vault reads, and AKS audit signals. The export kept only detection-relevant fields, removed original identities and resources, and replaced sensitive IPs. It is not a dump of complete raw logs, and it does not prove that every event was performed by one attacker or in the depicted sequence.

Replay assigns new identities, timestamps and a `RunId`, then sends these **synthetic copies** through the Azure Monitor Logs Ingestion API into dedicated custom tables. Three bundled scheduled analytics rules evaluate those tables and can create one Sentinel incident per selected scenario. The tool does not generate live attacks, native product events, or native Defender alerts.

## What is separated

| Scenario | Custom table | Required stages | Bundled rows |
| --- | --- | --- | ---: |
| S1 identity and mailbox | `IncidentLabS1_CL` | MFA denials, risky sign-in, app consent, mail forwarding, role assignment | 7 |
| S2 server | `IncidentLabS2_CL` | LSASS access, service installation, Security log clear | 4 |
| S3 platform | `IncidentLabS3_CL` | PAT use, service-principal secret, Container App write, Key Vault reads, AKS pod exec | 68 |

Each existing lab scenario has one table, one DCR, and one stable scheduled rule. A shared DCE serves all three. Selecting one rule replays only its records; selecting several replays those groups with a common `RunId` while keeping each incident separate. The alert and incident titles include that ID. We do **not** create one table or rule per run. All records are marked `IsSynthetic=true` and retain `SourceTable` only as a description of the original source represented. They are not written into those native tables. No additional detections are bundled.

## Prerequisites

1. Install [PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) (`pwsh`) and [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli). Check them with `pwsh --version` and `az version`. Check Bicep with `az bicep version`; if it is missing, run `az bicep install`. The script requires PowerShell 7 and uses Azure CLI for deployment, authentication, and Log Analytics queries.
2. Have an **existing Log Analytics workspace with Microsoft Sentinel enabled**. In the Azure portal, open Microsoft Sentinel and add it to your existing workspace if needed; follow [Microsoft's onboarding guide](https://learn.microsoft.com/en-us/azure/sentinel/quickstart-onboard). This tool never creates a workspace. You do not need Entra, Exchange, Windows, DevOps, AKS, or Defender data connectors for the synthetic replay.
3. Use an Azure identity that can manage a custom table in that workspace, create a DCE and DCR in its resource group, create Sentinel analytics rules, and assign a role on each DCR. Relevant built-in roles are Log Analytics Contributor on the workspace, Contributor on the resource group for DCE/DCR deployment, Microsoft Sentinel Contributor for rules, and User Access Administrator or Role Based Access Control Administrator for the DCR role assignment. Equivalent custom permissions also work. The deployment assigns the signed-in ingestor **Monitoring Metrics Publisher** on each DCR; you need query/incident read access for verification. The default interactive path uses your Azure CLI sign-in and does not need a separate app registration. See [table permissions](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/create-custom-table), [Sentinel roles](https://learn.microsoft.com/en-us/azure/sentinel/roles), and [Logs Ingestion API permissions](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview).
4. Allow HTTPS access to Azure sign-in, management, Log Analytics query, and the DCE's Logs Ingestion endpoint. Expect small ingestion/retention charges and enabled scheduled rules after deployment.

## First run

The template does not create a workspace. In this development project, the local ignored configuration targets the existing `DEV-Security-Monitoring` workspace. For your own workspace, fill in `config.json` with its subscription ID, tenant ID, resource group, name, and **workspace customer ID**. In the Azure portal the customer ID is the workspace ID on the workspace Overview; you can also retrieve it with `az monitor log-analytics workspace show -g <resource-group> -n <workspace-name> --query customerId -o tsv`.

On your own machine:

```powershell
git clone https://github.com/Pavel-Hrabec/Sentinel-Forge.git
Set-Location .\Sentinel-Forge
Copy-Item .\config.example.json .\config.json
# Edit config.json with your existing workspace IDs and your demo identities/IPs.
pwsh -NoProfile -File .\Start-IncidentLab.ps1 -Action Validate
```

Validation checks all three rule packs **offline**, without Azure calls. After it passes, sign in to the tenant and select the subscription from `config.json`:

```powershell
$settings = Get-Content .\config.json -Raw | ConvertFrom-Json
az login --tenant $settings.tenantId
az account set --subscription $settings.subscriptionId
pwsh -NoProfile -File .\Start-IncidentLab.ps1
```

Select `1`, `1,3`, `1-3`, `S1,S3`, or `All`; the menu shows each rule's name and its S1/S2/S3 coverage. `config.json` is ignored by Git and must not be committed.

Menu actions are **Preview and validate**, **Deploy only**, **Replay only**, **Deploy and replay**, and **Verify an earlier RunId**. Deployment creates the shared DCE once and then, per scenario, the table/DCR/RBAC and rule in two phases so the table can become queryable. Replay sends the bundled records via the Azure Monitor Logs Ingestion API. Verification waits for both the expected row count and an incident whose title contains the RunId. It prints the incident number and link. The script checks subscription, tenant, workspace ARM ID, and customer ID before any Azure write.

On a first deployment, Azure resource creation, initial table ingestion, five-minute rule scheduling, and incident synchronization can take several minutes. Use `-WaitMinutes 30` for an unattended first run. Subsequent replays skip healthy deployments, but each selected scenario must be outside its 20-minute alert suppression window. An accepted ingestion POST is not proof of an incident: the script checks both table rows and incident records.

Noninteractive examples:

```powershell
pwsh -NoProfile -File .\Start-IncidentLab.ps1 -Action Validate -Scenario S1
pwsh -NoProfile -File .\Start-IncidentLab.ps1 -Action All -Scenario 'S1,S3' -WaitMinutes 30
pwsh -NoProfile -File .\Start-IncidentLab.ps1 -Action Verify -Scenario S1 -RunId <guid>
```

`-Action All` deploys if needed, replays and verifies. `-Action Deploy` changes Azure resources without sending logs. `-Action Replay` requires a previous deployment. `-ForceDeploy` reapplies an edited table, DCR or rule; normal runs skip existing resources. For a service-principal login, use `-PrincipalId <object-id> -PrincipalType ServicePrincipal` and ensure the Azure CLI is signed in as that same principal. `-WaitMinutes 0` sends data without waiting. A preflight check blocks a second replay within the 20-minute rule suppression window, avoiding billable rows with no new incident.

To inspect one incident's evidence, replace the table and RunId:

```kusto
IncidentLabS1_CL
| where RunId == '<run-id>' and IsSynthetic == true
| extend Evidence = parse_json(Details)
| project TimeGenerated, Stage, SourceTable, Operation, Actor, Host, SourceIp, Target, Evidence
| order by TimeGenerated asc
```

## Source IP treatment

The original sanitized bundle removed **all** source IPs, so it could not preserve the attack-side addresses by itself. In this development checkout, ignored `config.json` contains the IPs recovered from controlled DEV test events for the rejected MFA prompts, risky sign-in, and PAT action. These are source IPs of test activity, not a claim that the IPs are inherently malicious. A known local address is kept only in `blockedLocalIps` in that ignored file: validation scans each complete outgoing payload and fails if it appears. Legitimate S1 activity uses the documentation-only address `198.51.100.28`; S2 and non-PAT S3 rows have an empty `SourceIp` because the sanitized source did not retain one. The public `config.example.json` contains only documentation IPs. Set its attack-side IP fields to your own known test/VPN IPs, and list any personal/local IPs under `blockedLocalIps`. Do not infer whether an IP is a VPN from geography alone.

Rule changes require `-Action Deploy -ForceDeploy`. Do not change a pack's table name or rule ID after deployment without a migration plan. Existing incidents are not deleted by this project. The bundled evidence was sanitized from DEV observations in November 2026; it is not proof that one attacker performed all actions or that the original timings formed one chronological sequence. S2's 1102 event shows a cleared Security log, not a stopped Windows Event Log service. S3 does not produce native Defender for Containers alerts. The three lab rules use custom tables and do **not** trigger similarly named native-table analytics rules.

## Cost and safety

This lab uses the **existing** workspace only. Analytics table ingestion/retention and Sentinel scheduled rules may incur charges. Each full replay sends 79 small records. The rules run every five minutes and remain enabled until disabled in Sentinel. Keep this in a development environment. Never delete the entire resource group to remove this project: it contains the pre-existing workspace and unrelated resources.

The bundled S1, S2, and S3 path was tested end to end in an existing DEV Sentinel workspace on 15 November 2026: 7, 4, and 68 rows arrived; all three scheduled rules created separate incidents with one alert each; the blocked local IP appeared in zero replay rows. Your incident numbers will differ.
