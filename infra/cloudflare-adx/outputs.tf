output "cloudflare_account_id" {
  value = var.cloudflare_account_id
}

output "tunnel_id" {
  value = cloudflare_zero_trust_tunnel_cloudflared.adx.id
}

output "public_hostname" {
  value = local.public_hostname
}

output "access_application_aud" {
  value = cloudflare_zero_trust_access_application.adx.aud
}