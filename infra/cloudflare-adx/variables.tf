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

variable "local_service" {
  description = "TCP endpoint for the private read-only Kusto gateway reached by Cloudflared."
  type        = string
  default     = "tcp://kusto-readonly-gateway:8081"
}

variable "student_service_token_duration" {
  description = "Lifetime of the shared workshop Service Auth credential. Rotate or delete it after the class."
  type        = string
  default     = "72h"

  validation {
    condition     = try(tonumber(regex("^([0-9]+)h$", var.student_service_token_duration)[0]) >= 48, false)
    error_message = "student_service_token_duration must be expressed in whole hours and be at least 48h."
  }
}

variable "student_service_token_name" {
  description = "Display name of the shared workshop Service Auth credential."
  type        = string
  default     = "Cyber Defense Workshop shared lab credential"
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