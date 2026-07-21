output "cloudflare_account_id" {
  value = var.cloudflare_account_id
}

output "tunnel_id" {
  value = cloudflare_zero_trust_tunnel_cloudflared.adx.id
}

output "public_hostname" {
  value = local.public_hostname
}

output "student_service_token_id" {
  value     = cloudflare_zero_trust_access_service_token.workshop.client_id
  sensitive = true
}

output "student_service_token_secret" {
  value     = cloudflare_zero_trust_access_service_token.workshop.client_secret
  sensitive = true
}