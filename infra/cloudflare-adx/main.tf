locals {
  public_hostname = "${var.hostname}.${var.zone_name}"
}

resource "random_id" "tunnel_secret" {
  byte_length = 35
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "adx" {
  account_id    = var.cloudflare_account_id
  config_src    = "cloudflare"
  name          = var.tunnel_name
  tunnel_secret = random_id.tunnel_secret.b64_std
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "adx" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.adx.id

  config = {
    ingress = [
      {
        hostname = local.public_hostname
        service  = var.local_service
      },
      {
        service = "http_status:404"
      }
    ]
  }
}

resource "cloudflare_dns_record" "adx" {
  count = var.manage_dns_with_api ? 1 : 0

  zone_id = var.cloudflare_zone_id
  name    = local.public_hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.adx.id}.cfargotunnel.com"
  ttl     = 1
  proxied = true
  comment = "Cyber Defense Workshop ADX Cloudflare Tunnel"
}

resource "cloudflare_zero_trust_access_identity_provider" "one_time_pin" {
  account_id = var.cloudflare_account_id
  name       = "Workshop one-time PIN"
  type       = "onetimepin"
  config     = {}
}

resource "cloudflare_zero_trust_access_application" "adx" {
  account_id           = var.cloudflare_account_id
  name                 = "Cyber Defense Workshop ADX"
  domain               = local.public_hostname
  type                 = "self_hosted"
  session_duration     = var.access_session_duration
  app_launcher_visible = false
  depends_on           = [cloudflare_zero_trust_access_identity_provider.one_time_pin]

  policies = [
    {
      name       = "Allow designated ADX users"
      precedence = 1
      decision   = "allow"
      include = [
        for allowed_email in var.allowed_emails : {
          email = {
            email = allowed_email
          }
        }
      ]
    }
  ]
}