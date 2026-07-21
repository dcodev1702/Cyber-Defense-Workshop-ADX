variable "cloudflare_account_id" {
  description = "Cloudflare account that owns the Zero Trust tunnel."
  type        = string
  default     = "14f094b46fd49577b3bf11f684fc735e"
}

variable "cloudflare_zone_id" {
  description = "Zone ID for tier1-cyberdefense.ai when Terraform manages DNS."
  type        = string
  default     = null
}

variable "zone_name" {
  description = "Cloudflare zone used for the public ADX hostname."
  type        = string
  default     = "tier1-cyberdefense.ai"
}

variable "hostname" {
  description = "Subdomain exposed through the Cloudflare Tunnel."
  type        = string
  default     = "adx"
}

variable "allowed_emails" {
  description = "Email addresses allowed through Cloudflare Access."
  type        = set(string)
}

variable "access_session_duration" {
  description = "Cloudflare Access session duration for the protected hostname."
  type        = string
  default     = "168h"
}

variable "local_service" {
  description = "Service URL reached by the cloudflared Compose service."
  type        = string
  default     = "tcp://kusto:8080"
}

variable "tunnel_name" {
  description = "Friendly name of the remotely managed Cloudflare Tunnel."
  type        = string
  default     = "cyber-conf-wiesbaden-kusto"
}

variable "manage_dns_with_api" {
  description = "Whether Terraform creates the public CNAME through the Cloudflare DNS API."
  type        = bool
  default     = false
}