@description('Name of an existing Sentinel-enabled Log Analytics workspace in this resource group.')
param workspaceName string

@description('Region of the existing workspace.')
param location string

param dceName string = 'sentinel-incident-lab-dce'
param scenarioId string
param tableName string
param ruleId string
param ruleDisplayName string
param ruleDescription string
@allowed(['High', 'Medium', 'Low', 'Informational'])
param severity string = 'High'
param query string
param ingestorPrincipalId string
@allowed(['User', 'ServicePrincipal'])
param ingestorPrincipalType string = 'User'
param deployRule bool = true
param enableRule bool = true

var streamName = 'Custom-${tableName}'
var dcrName = 'sentinel-incident-lab-${toLower(scenarioId)}-dcr'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' existing = {
  name: dceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: 30
    schema: {
      name: tableName
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'Scenario', type: 'string' }
        { name: 'RunId', type: 'string' }
        { name: 'Stage', type: 'string' }
        { name: 'SourceTable', type: 'string' }
        { name: 'Operation', type: 'string' }
        { name: 'Actor', type: 'string' }
        { name: 'Host', type: 'string' }
        { name: 'SourceIp', type: 'string' }
        { name: 'Target', type: 'string' }
        { name: 'Details', type: 'string' }
        { name: 'IsSynthetic', type: 'boolean' }
      ]
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: dcrName
  location: location
  tags: {
    Purpose: 'SyntheticSentinelIncidentLab'
    Scenario: scenarioId
  }
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      '${streamName}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Scenario', type: 'string' }
          { name: 'RunId', type: 'string' }
          { name: 'Stage', type: 'string' }
          { name: 'SourceTable', type: 'string' }
          { name: 'Operation', type: 'string' }
          { name: 'Actor', type: 'string' }
          { name: 'Host', type: 'string' }
          { name: 'SourceIp', type: 'string' }
          { name: 'Target', type: 'string' }
          { name: 'Details', type: 'string' }
          { name: 'IsSynthetic', type: 'boolean' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'sentinel'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['sentinel']
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [table]
}

resource ingestionAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, ingestorPrincipalId, '3913510d-42f4-4e42-8a64-420c390055eb')
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')
    principalId: ingestorPrincipalId
    principalType: ingestorPrincipalType
  }
}

resource rule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = if (deployRule) {
  name: ruleId
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: ruleDisplayName
    description: ruleDescription
    severity: severity
    enabled: enableRule
    query: query
    queryFrequency: 'PT5M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: true
    suppressionDuration: 'PT20M'
    eventGroupingSettings: { aggregationKind: 'AlertPerResult' }
    alertDetailsOverride: { alertDisplayNameFormat: '${ruleDisplayName} - {{RunId}}' }
    customDetails: { RunId: 'RunId' }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT2H'
        matchingMethod: 'Selected'
        groupByAlertDetails: ['DisplayName']
        groupByCustomDetails: ['RunId']
      }
    }
  }
  dependsOn: [table]
}

output tableName string = table.name
output dcrId string = dcr.id
output dcrImmutableId string = dcr.properties.immutableId
output streamName string = streamName
