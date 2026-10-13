# ─────────────────────────────────────────────────────────────
# FindingMerge.ps1
# Runs just before the report is built (New-AuditReport):
#   1. Normalises the resource type, so "Storage Account" (built-in checks) and
#      "Microsoft.Storage/storageAccounts" (Prowler, Advisor, WARA, PSRule) both become "Storage account".
#   2. Merges findings where several tools report the same problem on the same resource into one row
#      that lists every tool (Sources) and every check (CheckIds, Detections).
# Which checks mean "the same problem" is decided by $script:FindingTopics below.
# ─────────────────────────────────────────────────────────────

# Friendly names per ARM resource type (lower case). Types that are not listed get a name built
# from the type itself ("virtualNetworkGateways" -> "Virtual network gateway").
$script:ResourceTypeLabels = @{
    "microsoft.storage/storageaccounts"                     = "Storage account"
    "microsoft.web/sites"                                   = "App Service"
    "microsoft.web/sites/slots"                             = "App Service slot"
    "microsoft.web/serverfarms"                             = "App Service plan"
    "microsoft.web/staticsites"                             = "Static web app"
    "microsoft.web/connections"                             = "API connection"
    "microsoft.keyvault/vaults"                             = "Key vault"
    "microsoft.keyvault/managedhsms"                        = "Managed HSM"
    "microsoft.compute/virtualmachines"                     = "Virtual machine"
    "microsoft.compute/virtualmachinescalesets"             = "VM scale set"
    "microsoft.compute/disks"                               = "Managed disk"
    "microsoft.compute/snapshots"                           = "Disk snapshot"
    "microsoft.compute/availabilitysets"                    = "Availability set"
    "microsoft.network/networkinterfaces"                   = "Network interface"
    "microsoft.network/networksecuritygroups"               = "Network security group"
    "microsoft.network/networksecuritygroups/securityrules" = "NSG rule"
    "microsoft.network/publicipaddresses"                   = "Public IP address"
    "microsoft.network/virtualnetworks"                     = "Virtual network"
    "microsoft.network/virtualnetworks/subnets"             = "Subnet"
    "microsoft.network/loadbalancers"                       = "Load balancer"
    "microsoft.network/applicationgateways"                 = "Application gateway"
    "microsoft.network/azurefirewalls"                      = "Azure Firewall"
    "microsoft.network/virtualnetworkgateways"              = "VPN / ExpressRoute gateway"
    "microsoft.network/privateendpoints"                    = "Private endpoint"
    "microsoft.network/bastionhosts"                        = "Bastion host"
    "microsoft.network/natgateways"                         = "NAT gateway"
    "microsoft.network/frontdoors"                          = "Front Door (classic)"
    "microsoft.cdn/profiles"                                = "Front Door / CDN profile"
    "microsoft.network/privatednszones"                     = "Private DNS zone"
    "microsoft.network/dnszones"                            = "DNS zone"
    "microsoft.network/networkwatchers"                     = "Network Watcher"
    "microsoft.network/expressroutecircuits"                = "ExpressRoute circuit"
    "microsoft.sql/servers"                                 = "SQL server"
    "microsoft.sql/servers/databases"                       = "SQL database"
    "microsoft.sql/managedinstances"                        = "SQL managed instance"
    "microsoft.dbforpostgresql/flexibleservers"             = "PostgreSQL flexible server"
    "microsoft.dbformysql/flexibleservers"                  = "MySQL flexible server"
    "microsoft.documentdb/databaseaccounts"                 = "Cosmos DB account"
    "microsoft.cache/redis"                                 = "Azure Cache for Redis"
    "microsoft.containerservice/managedclusters"            = "AKS cluster"
    "microsoft.containerregistry/registries"                = "Container registry"
    "microsoft.app/containerapps"                           = "Container app"
    "microsoft.app/managedenvironments"                     = "Container Apps environment"
    "microsoft.containerinstance/containergroups"           = "Container instance"
    "microsoft.operationalinsights/workspaces"              = "Log Analytics workspace"
    "microsoft.insights/components"                         = "Application Insights"
    "microsoft.insights/actiongroups"                       = "Action group"
    "microsoft.recoveryservices/vaults"                     = "Recovery Services vault"
    "microsoft.dataprotection/backupvaults"                 = "Backup vault"
    "microsoft.automation/automationaccounts"               = "Automation account"
    "microsoft.logic/workflows"                             = "Logic app"
    "microsoft.eventhub/namespaces"                         = "Event Hubs namespace"
    "microsoft.servicebus/namespaces"                       = "Service Bus namespace"
    "microsoft.apimanagement/service"                       = "API Management"
    "microsoft.cognitiveservices/accounts"                  = "Azure AI services account"
    "microsoft.search/searchservices"                       = "Azure AI Search"
    "microsoft.datafactory/factories"                       = "Data factory"
    "microsoft.synapse/workspaces"                          = "Synapse workspace"
    "microsoft.databricks/workspaces"                       = "Databricks workspace"
    "microsoft.hybridcompute/machines"                      = "Arc-enabled server"
    "microsoft.managedidentity/userassignedidentities"      = "Managed identity"
    "microsoft.authorization/roleassignments"               = "Role assignment"
    "microsoft.authorization/policyassignments"             = "Policy assignment"
    "microsoft.security/pricings"                           = "Defender plan"
    "microsoft.resources/subscriptions"                     = "Subscription"
    "microsoft.resources/resourcegroups"                    = "Resource group"
    "microsoft.management/managementgroups"                 = "Management group"
    "microsoft.subscriptions/subscriptions"                 = "Subscription"
    "microsoft.keyvault/vaults/keys"                        = "Key vault key"
    "microsoft.keyvault/vaults/secrets"                     = "Key vault secret"
    "microsoft.keyvault.data/vaults/secrets"                = "Key vault secret"
    "microsoft.keyvault.data/vaults/keys"                   = "Key vault key"
    "microsoft.web/sites/config"                            = "App Service configuration"
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies" = "WAF policy (Application Gateway)"
    "microsoft.network/frontdoorwebapplicationfirewallpolicies"          = "WAF policy (Front Door)"
    "microsoft.network/routetables"                         = "Route table"
    "microsoft.network/privatednszones/virtualnetworklinks" = "Private DNS zone link"
    "microsoft.insights/activitylogalerts"                  = "Activity log alert"
    "microsoft.insights/metricalerts"                       = "Metric alert"
    "microsoft.insights/scheduledqueryrules"                = "Log search alert"
    "microsoft.insights/webtests"                           = "Availability test"
    "microsoft.insights/autoscalesettings"                  = "Autoscale setting"
    "microsoft.alertsmanagement/smartdetectoralertrules"    = "Smart detector alert rule"
    "microsoft.operationalinsights/querypacks"              = "Log Analytics query pack"
    "microsoft.automation/automationaccounts/runbooks"      = "Automation runbook"
    "microsoft.servicebus/namespaces/authorizationrules"    = "Service Bus authorization rule"
    "microsoft.authorization/roledefinitions"               = "Role definition"
    "microsoft.security/iotsecuritysolutions"               = "Defender for IoT solution"
    "microsoft.security/automations"                        = "Defender workflow automation"
    "microsoft.cache/redisenterprise"                       = "Azure Managed Redis"
    "microsoft.portal/dashboards"                           = "Dashboard"
    "microsoft.visualstudio/account"                        = "Azure DevOps organization"
}

# Other spellings of the same type (lower case) -> label. The labels above are matched as well.
$script:ResourceTypeAliases = @{
    "public ip"        = "Public IP address"
    "nsg"              = "Network security group"
    "vm"               = "Virtual machine"
    "web app"          = "App Service"
    "function app"     = "App Service"
    "kv certificate"   = "Key vault certificate"
    "microsoft.subscription" = "Subscription"
}

<#
  Topics: checks from different tools that report the same problem. Findings that match the same topic
  on the same resource become one row. A topic only takes effect when at least two different checks
  match it in this run; otherwise the finding keeps its own title.

    Id       stable key (used for the issue key in the report and the action plan)
    Title    title of the merged issue
    Types    ARM resource types (lower case, wildcards allowed). Empty = any resource type, except
             subscriptions, resource groups and role/policy assignments.
    ResourceGroups  optional; $true lets a topic with empty Types apply to resource groups too
    Pattern  regex on the check title + check ID (lower case, '_' '.' ':' replaced by spaces)
    Exclude  optional regex; a match means the topic does not apply

  The first matching topic wins, so put narrow topics before broad ones of the same resource type.
#>
$script:FindingTopics = @(
    # ── Storage accounts ────────────────────────────────────
    @{ Id = "storage-secure-transfer"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account allows HTTP (secure transfer not required)"
       Pattern = 'secure transfer|https|\bhttp\b|encrypted connections' }
    @{ Id = "storage-tls"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account minimum TLS version below 1.2"
       Pattern = '\btls\b|\bssl\b' }
    @{ Id = "storage-blob-public-access"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account allows anonymous (public) blob access"
       Pattern = 'blob ?public ?access|public blob|anonymous|public access level|allow ?blob ?public|public access should be disallowed'
       Exclude = 'network' }
    @{ Id = "storage-private-endpoint"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account does not use a private endpoint"
       Pattern = 'private ?(endpoint|link)' }
    @{ Id = "storage-trusted-services"; Types = @("microsoft.storage/storageaccounts")
       Title = "Trusted Azure services cannot reach the storage account"
       Pattern = 'trusted (microsoft |azure )?services' }
    @{ Id = "storage-public-network"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account allows public network access"
       Pattern = 'public network access|default network access|network access rule|network acl|firewall|selected networks|all networks|allowed traffic|virtual network (rules|configurations)|service endpoint|restrict network' }
    @{ Id = "storage-key-rotation"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account access keys are not rotated"
       Pattern = 'rotat|regenerat|key expir|expiration' }
    @{ Id = "storage-shared-key"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account allows shared key access"
       Pattern = 'shared ?key|key.?based (auth|access)|local ?auth|access keys? allow' }
    @{ Id = "storage-container-soft-delete"; Types = @("microsoft.storage/storageaccounts")
       Title = "Container soft delete not enabled"
       Pattern = 'soft ?delete|deleted containers'; Exclude = 'blob|file share|\bfiles\b|^(?!.*container)' }
    @{ Id = "storage-fileshare-soft-delete"; Types = @("microsoft.storage/storageaccounts")
       Title = "File share soft delete not enabled"
       Pattern = 'soft ?delete'; Exclude = '^(?!.*(file share|\bfiles\b))' }
    @{ Id = "storage-blob-soft-delete"; Types = @("microsoft.storage/storageaccounts")
       Title = "Blob soft delete not enabled"
       Pattern = 'soft ?delete|deleted blobs' }
    @{ Id = "storage-versioning"; Types = @("microsoft.storage/storageaccounts")
       Title = "Blob versioning not enabled"
       Pattern = 'versioning' }
    @{ Id = "storage-redundancy"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account is not zone or geo redundant"
       Pattern = '\bzones?\b|zone.?redundan|redundan|geo.?replicat|\b(grs|zrs|gzrs|ra.?grs|lrs)\b|use ?replication'
       Exclude = 'cross.?tenant|object replication' }
    @{ Id = "storage-infrastructure-encryption"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account infrastructure (double) encryption not enabled"
       Pattern = 'infrastructure encryption|double encryption' }
    @{ Id = "storage-cross-tenant"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account allows cross-tenant replication"
       Pattern = 'cross.?tenant' }
    @{ Id = "storage-gpv1"; Types = @("microsoft.storage/storageaccounts")
       Title = "Storage account is a legacy general-purpose v1 account (upgrade to v2)"
       Pattern = 'general.?purpose v1|\bgpv1\b|legacy storage|v2 storage' }

    # ── Key Vault ───────────────────────────────────────────
    @{ Id = "keyvault-purge-protection"; Types = @("microsoft.keyvault/vaults", "microsoft.keyvault/managedhsms")
       Title = "Key Vault purge protection disabled"
       Pattern = 'purge protection|deletion protection' }
    @{ Id = "keyvault-soft-delete"; Types = @("microsoft.keyvault/vaults", "microsoft.keyvault/managedhsms")
       Title = "Key Vault soft delete disabled"
       Pattern = 'soft ?delete|recoverable' }
    # Before RBAC: Prowler's "Expiration Date ... in Non-RBAC Key Vaults" is about expiry
    @{ Id = "keyvault-expiry"; Types = @("microsoft.keyvault/vaults", "microsoft.keyvault/vaults/*", "microsoft.keyvault.data/vaults/*")
       Title = "Key Vault secrets or keys without an expiry date"
       Pattern = '(keys?|secrets?)\b.*expir|expir.*\b(keys?|secrets?)\b'; Exclude = 'certificate' }
    @{ Id = "keyvault-rbac"; Types = @("microsoft.keyvault/vaults")
       Title = "Key Vault does not use the RBAC permission model"
       Pattern = '\brbac\b|role.?based access|access polic|permission model' }
    @{ Id = "keyvault-public-network"; Types = @("microsoft.keyvault/vaults")
       Title = "Key Vault allows public network access"
       Pattern = 'public network access|firewall|allowed traffic|service endpoint|network acl|selected networks|all networks' }

    # ── App Service ─────────────────────────────────────────
    @{ Id = "appservice-http2"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service does not use HTTP/2"
       Pattern = 'http ?2|http version' }
    @{ Id = "appservice-https"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service does not enforce HTTPS"
       Pattern = 'https|redirect.*\bhttp\b|\bhttp\b.*redirect' }
    @{ Id = "appservice-tls"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service minimum TLS version below 1.2"
       Pattern = '\btls\b|\bssl\b' }
    @{ Id = "appservice-ftp"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service allows FTP"
       Pattern = '\bftps?\b' }
    @{ Id = "appservice-client-cert"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service does not require client certificates"
       Pattern = 'client cert|incoming client' }
    @{ Id = "appservice-remote-debug"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service remote debugging enabled"
       Pattern = 'remote debug' }
    @{ Id = "appservice-auth"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service authentication not enabled"
       Pattern = 'app service auth|easy ?auth|authentication' }
    @{ Id = "appservice-health-check"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service health check (health probe) not configured"
       Pattern = 'health ?check|health probe|webprobe' }
    @{ Id = "appservice-dotnet"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service runs an outdated .NET version"
       Pattern = '\bnet (\d|versions?)|netversion|dotnet' }
    @{ Id = "appservice-php"; Types = @("microsoft.web/sites", "microsoft.web/sites/slots")
       Title = "App Service runs an outdated PHP version"
       Pattern = '\bphp' }

    # ── Virtual machines ────────────────────────────────────
    @{ Id = "vm-backup"; Types = @("microsoft.compute/virtualmachines")
       Title = "Virtual machine is not backed up"
       Pattern = 'backup' }
    @{ Id = "vm-disk-encryption"; Types = @("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets")
       Title = "VM disks not encrypted (ADE / encryption at host)"
       Pattern = 'encrypt' }
    @{ Id = "vm-managed-disks"; Types = @("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets")
       Title = "Virtual machine does not use managed disks"
       Pattern = 'managed disk|unmanaged disk' }
    @{ Id = "vm-endpoint-protection"; Types = @("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets", "microsoft.hybridcompute/machines")
       Title = "Endpoint protection missing on the machine"
       Pattern = 'endpoint protection|anti.?malware|\bedr\b' }
    @{ Id = "vm-updates"; Types = @("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets", "microsoft.hybridcompute/machines")
       Title = "Machine is missing system updates"
       Pattern = 'system updates|missing (security )?updates|update manager|periodic assessment|\bpatch'
       Exclude = 'cve-' }
    @{ Id = "vm-jit"; Types = @("microsoft.compute/virtualmachines")
       Title = "Management ports not protected by just-in-time access"
       Pattern = 'just.?in.?time|\bjit\b' }
    @{ Id = "vm-trusted-launch"; Types = @("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets")
       Title = "Trusted launch (secure boot / vTPM) not enabled"
       Pattern = 'trusted launch|secure boot|vtpm' }
    @{ Id = "vm-monitoring-agent"; Types = @("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets", "microsoft.hybridcompute/machines")
       Title = "Monitoring agent not installed"
       Pattern = 'monitor(ing)? agent|azure monitor agent|\bama\b|log analytics agent' }

    # ── Network security groups ─────────────────────────────
    @{ Id = "nsg-flow-logs"; Types = @("microsoft.network/networksecuritygroups")
       Title = "NSG flow logs not enabled"
       Pattern = 'flow ?log' }
    @{ Id = "nsg-internet-ports"; Types = @("microsoft.network/networksecuritygroups", "microsoft.network/networksecuritygroups/securityrules")
       Title = "Management or database ports open to the Internet"
       Pattern = '\brdp\b|\bssh\b|\bwinrm\b|\budp\b|3389|management port|database port|internet|0 0 0 0|any source|unrestricted' }

    # ── SQL ─────────────────────────────────────────────────
    @{ Id = "sql-auditing"; Types = @("microsoft.sql/servers", "microsoft.sql/servers/databases", "microsoft.sql/managedinstances")
       Title = "SQL auditing not enabled"
       Pattern = '\baudit' }
    @{ Id = "sql-entra-admin"; Types = @("microsoft.sql/servers", "microsoft.sql/managedinstances", "microsoft.dbforpostgresql/flexibleservers", "microsoft.dbformysql/flexibleservers")
       Title = "Database server has no Microsoft Entra administrator / Entra-only authentication"
       Pattern = '\bentra\b|azure ad|azure active directory|\baad\b' }
    @{ Id = "sql-defender"; Types = @("microsoft.sql/servers", "microsoft.sql/managedinstances")
       Title = "Defender for SQL / vulnerability assessment not enabled"
       Pattern = 'defender|advanced (data security|threat)|vulnerability assessment'; Exclude = 'cve-' }
    @{ Id = "sql-tde"; Types = @("microsoft.sql/servers", "microsoft.sql/servers/databases", "microsoft.sql/managedinstances")
       Title = "SQL transparent data encryption not enabled or not using customer-managed keys"
       Pattern = '\btde\b|transparent data encryption' }
    @{ Id = "db-ssl"; Types = @("microsoft.dbforpostgresql/*", "microsoft.dbformysql/*", "microsoft.cache/redis")
       Title = "Database does not enforce encrypted (SSL/TLS) connections"
       Pattern = '\bssl\b|\btls\b|secure transport|non.?ssl port' }

    # ── Containers ──────────────────────────────────────────
    @{ Id = "acr-admin-user"; Types = @("microsoft.containerregistry/registries")
       Title = "Container registry admin user enabled"
       Pattern = 'admin (user|account)' }
    @{ Id = "acr-sku"; Types = @("microsoft.containerregistry/registries")
       Title = "Container registry does not use the Premium tier"
       Pattern = 'premium tier|basic sku|minsku' }
    @{ Id = "aks-rbac"; Types = @("microsoft.containerservice/managedclusters")
       Title = "AKS cluster does not use Entra ID integration / Azure RBAC"
       Pattern = '\brbac\b|\bentra\b|azure ad|\baad\b' }
    @{ Id = "aks-local-accounts"; Types = @("microsoft.containerservice/managedclusters")
       Title = "AKS local accounts enabled"
       Pattern = 'local account' }
    @{ Id = "aks-api-access"; Types = @("microsoft.containerservice/managedclusters")
       Title = "AKS API server is publicly reachable"
       Pattern = 'private cluster|api server|authorized ip' }
    @{ Id = "aks-network-policy"; Types = @("microsoft.containerservice/managedclusters")
       Title = "AKS network policy not enabled"
       Pattern = 'network polic' }

    # ── API Management ──────────────────────────────────────
    @{ Id = "apim-unencrypted"; Types = @("microsoft.apimanagement/service")
       Title = "API Management allows unencrypted (HTTP) communication"
       Pattern = 'encrypted protocols|unencrypted communication|httpendpoint|httpbackend' }
    @{ Id = "apim-named-values"; Types = @("microsoft.apimanagement/service")
       Title = "API Management secret named values are not stored in Key Vault"
       Pattern = 'named values|encryptvalues' }

    # ── Virtual networks ────────────────────────────────────
    @{ Id = "vnet-ddos"; Types = @("microsoft.network/virtualnetworks", "microsoft.networking/virtualnetworks")
       Title = "Virtual network has no DDoS Network Protection"
       Pattern = '\bddos\b' }
    @{ Id = "vnet-outbound"; Types = @("microsoft.network/virtualnetworks", "microsoft.network/virtualnetworks/subnets")
       Title = "Subnets use default outbound Internet access (no NAT gateway)"
       Pattern = 'nat gateway|direct outbound|default outbound|privatesubnet' }

    # ── Subscription settings ───────────────────────────────
    @{ Id = "service-health-alert"; Types = @("microsoft.resources/subscriptions")
       Title = "No Service Health alert configured"
       Pattern = 'service health' }
    @{ Id = "defender-auto-provisioning"; Types = @("microsoft.resources/subscriptions")
       Title = "Defender for Cloud auto-provisioning not enabled"
       Pattern = 'auto.?provisioning' }

    # ── Any resource type ───────────────────────────────────
    @{ Id = "private-endpoint"; Types = @()
       Title = "Resource does not use a private endpoint"
       Pattern = 'private ?(endpoint|link)' }
    @{ Id = "public-network-access"; Types = @()
       Title = "Resource allows public network access"
       Pattern = 'public network access|publicnetworkaccess|network access|network acl|\bfirewall\b|selected networks|all networks|public networks|ip rules|virtual network rules|service endpoint|publicly accessible|allowed traffic'
       Exclude = 'web application firewall|\bwaf\b|azure firewall' }
    @{ Id = "zone-redundancy"; Types = @()
       Title = "Resource is not zone redundant"
       Pattern = '\bzones?\b|zonal|zone.?redundan'; Exclude = 'dns zone|private dns' }
    @{ Id = "geo-redundancy"; Types = @()
       Title = "Resource is not geo redundant"
       Pattern = 'geo.?(redundan|replicat|replica)|paired region|multi.?region|multiple (azure )?regions|region redundan' }
    @{ Id = "diagnostic-logs"; Types = @()
       Title = "Diagnostic settings / resource logs not configured"
       Pattern = 'diagnostic|resource logs?|\blogging\b' }
    @{ Id = "customer-managed-key"; Types = @()
       Title = "Data not encrypted with a customer-managed key"
       Pattern = 'customer.?managed key|\bcmk\b' }
    @{ Id = "minimum-tls"; Types = @()
       Title = "Minimum TLS version below 1.2"
       Pattern = '\btls\b' }
    @{ Id = "managed-identity"; Types = @()
       Title = "Resource does not use a managed identity"
       Pattern = 'managed identit' }
    @{ Id = "local-auth"; Types = @()
       Title = "Local (key-based) authentication enabled"
       Pattern = 'local ?auth|key.?based auth|access keys?|disable ?(local|key)|only authentication method'; Exclude = 'rotat|regenerat|expir' }
    @{ Id = "backup"; Types = @()
       Title = "Resource is not backed up"
       Pattern = '\bbackups?\b' }
    @{ Id = "resource-lock"; Types = @()
       Title = "Resource lock not configured"
       Pattern = 'resource lock|\block\b' }
    @{ Id = "tags"; Types = @(); ResourceGroups = $true
       Title = "Resource is missing required tags"
       Pattern = '\btags?\b|tagged|tagging' }
)

# Tool order used to pick the main source of a merged row (its category and recommendation).
$script:SourcePriority = @("Native", "Defender for Cloud", "Prowler", "PSRule", "Azure Advisor", "WARA", "Maester", "AzGovViz")

function Get-ArmTypeFromId {
    # "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Sql/servers/s/databases/d" -> "microsoft.sql/servers/databases"
    param([AllowEmptyString()][string]$ResourceId)
    $id = "$ResourceId".Trim().TrimEnd('/')
    if (-not $id.StartsWith('/')) { return "" }
    $lower = $id.ToLowerInvariant()
    $idx = $lower.LastIndexOf('/providers/')
    if ($idx -ge 0) {
        $parts = @($lower.Substring($idx + 11) -split '/' | Where-Object { $_ })
        if ($parts.Count -lt 2) { return "" }
        $types = for ($i = 1; $i -lt $parts.Count; $i += 2) { $parts[$i] }
        return "$($parts[0])/$(@($types) -join '/')"
    }
    if ($lower -match '^/subscriptions/[^/]+/resourcegroups/[^/]+$') { return "microsoft.resources/resourcegroups" }
    if ($lower -match '^/subscriptions/[^/]+$') { return "microsoft.resources/subscriptions" }
    return ""
}

function Get-ResourceTypeLabel {
    # Friendly name for an ARM type: from the table, or built from the last segment of the type.
    param([AllowEmptyString()][string]$ArmType)
    $t = "$ArmType".ToLowerInvariant()
    if (-not $t) { return "" }
    if ($script:ResourceTypeLabels.ContainsKey($t)) { return $script:ResourceTypeLabels[$t] }
    # Keep the original casing when the caller passed it ("Microsoft.Network/virtualNetworkGateways")
    $last = ("$ArmType" -split '/')[-1]
    $words = ($last -creplace '([a-z0-9])([A-Z])', '$1 $2').ToLowerInvariant()
    if ($words -match '[^s]s$') { $words = $words.Substring(0, $words.Length - 1) }
    if (-not $words) { return "$ArmType" }
    return $words.Substring(0, 1).ToUpperInvariant() + $words.Substring(1)
}

function Resolve-FindingResourceType {
    <#
      Returns @{ ArmType; Label } for a finding.
        - An ARM type ("Microsoft.Storage/storageAccounts") is translated to its label.
        - A known friendly name ("Storage Account") gets the same label as its ARM type.
        - Anything else falls back to the type in the resource ID, or is kept as it is.
    #>
    param([AllowEmptyString()][string]$ResourceType, [AllowEmptyString()][string]$ResourceId)
    $given = "$ResourceType".Trim()
    $fromId = Get-ArmTypeFromId $ResourceId

    if ($given -match '^[A-Za-z0-9]+\.[A-Za-z0-9.]+/[A-Za-z0-9/]+$') {
        $arm = $given.ToLowerInvariant()
        return @{ ArmType = $(if ($fromId) { $fromId } else { $arm }); Label = (Get-ResourceTypeLabel $given) }
    }
    $key = $given.ToLowerInvariant()
    if ($key -and $key -ne "unknown") {
        if ($script:ResourceTypeAliases.ContainsKey($key)) { return @{ ArmType = $fromId; Label = $script:ResourceTypeAliases[$key] } }
        $match = $script:ResourceTypeLabels.GetEnumerator() | Where-Object { $_.Value.ToLowerInvariant() -eq $key } | Select-Object -First 1
        if ($match) { return @{ ArmType = $(if ($fromId) { $fromId } else { $match.Key }); Label = $match.Value } }
        # A specific name from a tool ("Defender plan", "Microsoft Entra tenant") is kept, unless the
        # resource ID tells a type we have a name for.
        if ($fromId -and $script:ResourceTypeLabels.ContainsKey($fromId) -and $given -notmatch '\s') {
            return @{ ArmType = $fromId; Label = $script:ResourceTypeLabels[$fromId] }
        }
        return @{ ArmType = $fromId; Label = $given }
    }
    if ($fromId) { return @{ ArmType = $fromId; Label = (Get-ResourceTypeLabel $fromId) } }
    return @{ ArmType = ""; Label = $(if ($given) { $given } else { "" }) }
}

function Get-FindingTopic {
    # Id of the first topic that matches the finding, or "".
    param([Parameter(Mandatory)]$Finding, [AllowEmptyString()][string]$ArmType)
    if (-not $ArmType) { return "" }
    if ("$($Finding.Vulnerabilities)".Trim()) { return "" }          # CVE findings are per vulnerability, not per topic
    if ("$($Finding.CheckId)" -like "WARA-RETIREMENT*") { return "" }
    $scopeOnly = $ArmType -match '^microsoft\.(resources|authorization|management)/'
    $text = (("$($Finding.Title) $($Finding.CheckId)").ToLowerInvariant() -replace '[_.:]+', ' ')

    foreach ($topic in $script:FindingTopics) {
        $types = @($topic.Types)
        if ($types.Count -gt 0) {
            if (-not ($types | Where-Object { $ArmType -like $_ })) { continue }
        }
        elseif ($scopeOnly -and -not ($topic['ResourceGroups'] -and $ArmType -eq "microsoft.resources/resourcegroups")) { continue }
        if ($text -notmatch $topic.Pattern) { continue }
        if ($topic['Exclude'] -and $text -match $topic.Exclude) { continue }
        return $topic.Id
    }
    return ""
}

function Merge-AuditFindings {
    <#
      Returns a new list of findings (the input is not changed) where:
        - ResourceType is normalised (see Resolve-FindingResourceType).
        - Findings on the same resource that match the same topic are one row. The row keeps the
          highest severity, lists every tool in Sources and every check in CheckIds, and keeps each
          tool's own title and detail in Detections.
      Every row gets Sources, CheckIds, Topic and Detections, so the report can treat all rows alike.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)

    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $srcRank = @{}; for ($n = 0; $n -lt $script:SourcePriority.Count; $n++) { $srcRank[$script:SourcePriority[$n]] = $n }
    $topicsById = @{}; foreach ($t in $script:FindingTopics) { $topicsById[$t.Id] = $t }

    # 1. Resource type and topic per finding
    $rows = foreach ($f in $Findings) {
        $type = Resolve-FindingResourceType -ResourceType "$($f.ResourceType)" -ResourceId "$($f.ResourceId)"
        $resKey = "$($f.ResourceId)".Trim().TrimEnd('/').ToLowerInvariant()
        [PSCustomObject]@{
            F       = $f
            Label   = $type.Label
            Topic   = $(if ($resKey) { Get-FindingTopic -Finding $f -ArmType $type.ArmType } else { "" })
            ResKey  = $resKey
            CheckKey = "$($f.Source)::$(if ($f.CheckId) { $f.CheckId } else { $f.Title })"
        }
    }
    $rows = @($rows)

    # 2. A topic is only used when two or more different checks match it (otherwise nothing is merged
    #    and the finding keeps its own, more precise, title).
    $checksPerTopic = @{}
    foreach ($r in $rows) {
        if (-not $r.Topic) { continue }
        if (-not $checksPerTopic.ContainsKey($r.Topic)) { $checksPerTopic[$r.Topic] = @{} }
        $checksPerTopic[$r.Topic][$r.CheckKey] = $true
    }
    foreach ($r in $rows) {
        if ($r.Topic -and $checksPerTopic[$r.Topic].Count -lt 2) { $r.Topic = "" }
    }

    # 3. Build the output rows
    $result = [System.Collections.Generic.List[PSCustomObject]]::new()
    $groups = [ordered]@{}
    foreach ($r in $rows) {
        if (-not $r.Topic) {
            $f = $r.F
            $result.Add([PSCustomObject]@{
                Source = $f.Source; Sources = "$($f.Source)"; Category = $f.Category; Severity = $f.Severity
                CheckId = $f.CheckId; CheckIds = "$($f.CheckId)"; Topic = ""; Title = $f.Title
                Resource = $f.Resource; ResourceType = $r.Label; ResourceId = $f.ResourceId; SubscriptionId = $f.SubscriptionId
                Finding = $f.Finding; Recommendation = $f.Recommendation; Reference = $f.Reference; Frameworks = $f.Frameworks
                Vulnerabilities = $f.Vulnerabilities; Timestamp = $f.Timestamp; Detections = @()
            })
            continue
        }
        $key = "$($r.Topic)|$($r.ResKey)"
        if (-not $groups.Contains($key)) { $groups[$key] = [System.Collections.Generic.List[object]]::new() }
        $groups[$key].Add($r)
    }

    foreach ($key in $groups.Keys) {
        $members = @($groups[$key])
        $topic = $topicsById[$members[0].Topic]
        $ordered = @($members | Sort-Object @{ Expression = { if ($srcRank.ContainsKey($_.F.Source)) { $srcRank[$_.F.Source] } else { 99 } } },
                                            @{ Expression = { $sevRank["$($_.F.Severity)"] } })
        $main = $ordered[0].F
        $worst = ($ordered | Sort-Object @{ Expression = { $sevRank["$($_.F.Severity)"] } } | Select-Object -First 1).F.Severity

        $sources = @($ordered | ForEach-Object { "$($_.F.Source)" } | Select-Object -Unique)
        $checkIds = @($ordered | ForEach-Object { "$($_.F.CheckId)" } | Where-Object { $_ } | Select-Object -Unique)
        $frameworks = @($ordered | ForEach-Object { "$($_.F.Frameworks)" } | Where-Object { $_ } | Select-Object -Unique)
        $reference = @($ordered | ForEach-Object { "$($_.F.Reference)" } | Where-Object { $_ } | Select-Object -First 1)

        # One detail per tool: "Prowler: <detail>"
        $details = [System.Collections.Generic.List[string]]::new()
        foreach ($m in $ordered) {
            $text = if ("$($m.F.Finding)" -and "$($m.F.Finding)" -ne "$($m.F.Title)") { "$($m.F.Finding)" } else { "$($m.F.Title)" }
            $line = "$($m.F.Source): $text"
            if (-not $details.Contains($line)) { $details.Add($line) }
        }

        $result.Add([PSCustomObject]@{
            Source = $main.Source; Sources = ($sources -join ", "); Category = $main.Category; Severity = $worst
            CheckId = $main.CheckId; CheckIds = ($checkIds -join ", "); Topic = $topic.Id; Title = $topic.Title
            Resource = $(if ($main.Resource) { $main.Resource } else { ($ordered | Where-Object { $_.F.Resource } | Select-Object -First 1).F.Resource })
            ResourceType = $members[0].Label; ResourceId = $main.ResourceId; SubscriptionId = $main.SubscriptionId
            Finding = ($details -join " | "); Recommendation = $main.Recommendation
            Reference = $(if ($main.Reference) { $main.Reference } else { "$($reference | Select-Object -First 1)" })
            Frameworks = ($frameworks -join "; "); Vulnerabilities = ""; Timestamp = $main.Timestamp
            Detections = @($ordered | ForEach-Object {
                [PSCustomObject]@{ Source = $_.F.Source; CheckId = $_.F.CheckId; Title = $_.F.Title; Severity = $_.F.Severity; Category = $_.F.Category }
            })
        })
    }

    # Rows without a type take the type that other rows on the same resource have
    $typeByResource = @{}
    foreach ($row in $result) {
        $k = "$($row.ResourceId)".TrimEnd('/').ToLowerInvariant()
        if (-not $k -or -not $row.ResourceType) { continue }
        if (-not $typeByResource.ContainsKey($k)) { $typeByResource[$k] = $row.ResourceType }
    }
    foreach ($row in $result) {
        $k = "$($row.ResourceId)".TrimEnd('/').ToLowerInvariant()
        if ($k -and -not $row.ResourceType -and $typeByResource.ContainsKey($k)) { $row.ResourceType = $typeByResource[$k] }
    }

    return , $result
}
