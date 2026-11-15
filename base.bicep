@description('Region of the existing Log Analytics workspace.')
param location string

@description('Shared Logs Ingestion API endpoint name.')
param dceName string = 'sentinel-incident-lab-dce'

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: dceName
  location: location
  tags: {
    Purpose: 'SyntheticSentinelIncidentLab'
  }
  properties: {
    description: 'Shared endpoint for synthetic scenario replay.'
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

output dceId string = dce.id
output logsIngestionEndpoint string = dce.properties.logsIngestion.endpoint
