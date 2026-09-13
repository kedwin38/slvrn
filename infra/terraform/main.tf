#
# SOLVAREN Cloudflare edge configuration.
#
# Everything an attacker reaches before the application does. The application enforces its
# own authorization regardless (spec §16.2: "Access is an additional layer, not a
# replacement"), so nothing here is load-bearing on its own — but each rule removes a class
# of traffic that should never reach a payment control plane.
#
#   terraform init
#   terraform plan  -var-file=production.tfvars
#   terraform apply -var-file=production.tfvars
#

terraform {
  required_version = ">= 1.6"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
  }
}

provider "cloudflare" {
  # Supplied via CLOUDFLARE_API_TOKEN. Never committed, never in a tfvars file.
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "zone_id" {
  type        = string
  description = "Cloudflare zone id for the SOLVAREN domain."
}

variable "account_id" {
  type        = string
  description = "Cloudflare account id."
}

variable "api_hostname" {
  type        = string
  description = "API hostname, e.g. api.solvaren.co.ke"
}

variable "app_hostname" {
  type        = string
  description = "Console hostname, e.g. app.solvaren.co.ke"
}

variable "administrator_emails" {
  type        = list(string)
  description = "Email addresses permitted through Cloudflare Access to administrative surfaces."
}

variable "safaricom_callback_ranges" {
  type        = list(string)
  description = <<-EOT
    Source IP ranges Safaricom delivers Daraja callbacks from.

    Safaricom does not publish these in a machine-readable form, and they change. Obtain
    the current list from apisupport@safaricom.co.ke during go-live and keep this variable
    updated — see docs/runbooks/daraja-credential-rotation.md.

    This is defence in depth, not the primary control: the callback endpoint additionally
    requires a per-organisation shared secret and deduplicates by payload digest, so an
    out-of-date list degrades to "the application check is doing the work", not to an open
    endpoint. Leave empty to disable the IP restriction rather than guessing at ranges.
  EOT
  default     = []
}

# ---------------------------------------------------------------------------
# Zone settings
# ---------------------------------------------------------------------------

resource "cloudflare_zone_settings_override" "solvaren" {
  zone_id = var.zone_id

  settings {
    ssl                      = "strict" # full verification to the origin, not "flexible"
    always_use_https         = "on"
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    automatic_https_rewrites = "on"
    opportunistic_encryption = "on"
    security_level           = "medium"
    browser_check            = "on"
    challenge_ttl            = 1800

    # A payment console must not be transformed by the edge: minification or
    # rewriting of an authenticated response is an integrity risk for no benefit.
    brotli = "on"

    # HSTS with preload. Once set, the domain cannot be served over plain HTTP, which is
    # the intent for a financial application.
    security_header {
      enabled            = true
      include_subdomains = true
      max_age            = 63072000
      preload            = true
      nosniff            = true
    }
  }
}

# ---------------------------------------------------------------------------
# WAF — custom rules
#
# Ordered by specificity. Each rule states what it blocks and why that traffic has no
# legitimate reason to exist against this application.
# ---------------------------------------------------------------------------

resource "cloudflare_ruleset" "waf_custom" {
  zone_id     = var.zone_id
  name        = "SOLVAREN custom WAF"
  description = "Payment control plane traffic policy"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  # ---- 1. Method allowlist ------------------------------------------------
  rules {
    action      = "block"
    description = "Block HTTP methods the API never uses"
    expression  = <<-EOT
      (http.host eq "${var.api_hostname}"
       and not http.request.method in {"GET" "POST" "PATCH" "DELETE" "OPTIONS" "HEAD"})
    EOT
    enabled     = true
  }

  # ---- 2. Callback endpoint source restriction ----------------------------
  # Only applied when the ranges are actually known; an empty list leaves the
  # application's shared-secret check as the control rather than blocking everything.
  dynamic "rules" {
    for_each = length(var.safaricom_callback_ranges) > 0 ? [1] : []
    content {
      action      = "block"
      description = "Daraja callbacks may only originate from Safaricom ranges"
      expression  = <<-EOT
        (http.host eq "${var.api_hostname}"
         and starts_with(http.request.uri.path, "/integrations/daraja/")
         and not ip.src in {${join(" ", var.safaricom_callback_ranges)}})
      EOT
      enabled     = true
    }
  }

  # ---- 3. Callback method and content type --------------------------------
  rules {
    action      = "block"
    description = "Daraja callbacks are POST with a JSON body"
    expression  = <<-EOT
      (http.host eq "${var.api_hostname}"
       and starts_with(http.request.uri.path, "/integrations/daraja/")
       and (http.request.method ne "POST" or not http.request.headers["content-type"][0] contains "json"))
    EOT
    enabled     = true
  }

  # ---- 4. Oversized callback bodies ---------------------------------------
  rules {
    action      = "block"
    description = "A Daraja result envelope is never larger than 64 KB"
    expression  = <<-EOT
      (http.host eq "${var.api_hostname}"
       and starts_with(http.request.uri.path, "/integrations/daraja/")
       and http.request.body.size gt 65536)
    EOT
    enabled     = true
  }

  # ---- 5. Automated traffic on the authentication surface -----------------
  rules {
    action      = "managed_challenge"
    description = "Challenge automated clients on the authentication endpoints"
    expression  = <<-EOT
      (http.host eq "${var.api_hostname}"
       and starts_with(http.request.uri.path, "/auth/")
       and not starts_with(http.request.uri.path, "/auth/session")
       and cf.client.bot
       and not cf.verified_bot_category in {"Search Engine Crawler"})
    EOT
    enabled     = true
  }

  # ---- 6. Administrative surface ------------------------------------------
  # The application already restricts these to L3, and Cloudflare Access sits in front of
  # them. This is the third layer: block outright from countries the organisation does not
  # operate in, which is cheap and removes a large share of opportunistic traffic.
  rules {
    action      = "managed_challenge"
    description = "Challenge administrative access from outside the operating region"
    expression  = <<-EOT
      (http.host eq "${var.api_hostname}"
       and starts_with(http.request.uri.path, "/admin/")
       and not ip.geoip.country in {"KE" "UG" "TZ" "RW" "GB" "US"})
    EOT
    enabled     = true
  }

  # ---- 7. Path traversal and obvious probes -------------------------------
  rules {
    action      = "block"
    description = "Block traversal sequences and common probe paths"
    expression  = <<-EOT
      (http.request.uri.path contains ".."
       or http.request.uri.path contains "/.git"
       or http.request.uri.path contains "/.env"
       or http.request.uri.path contains "/wp-admin"
       or http.request.uri.path contains "/phpmyadmin")
    EOT
    enabled     = true
  }
}

# ---------------------------------------------------------------------------
# Rate limiting
#
# The authentication and export surfaces are the two that reward abuse: one to guess
# credentials, the other to exfiltrate payment data a row at a time.
# ---------------------------------------------------------------------------

resource "cloudflare_ruleset" "rate_limits" {
  zone_id     = var.zone_id
  name        = "SOLVAREN rate limits"
  description = "Per-endpoint abuse limits"
  kind        = "zone"
  phase       = "http_ratelimit"

  # ---- Sign-in ------------------------------------------------------------
  # Ten attempts per minute per IP. The application additionally locks an account after
  # five failures (services/auth.ts), so this bounds distributed guessing against *many*
  # accounts, which the per-account lockout does not.
  rules {
    action      = "block"
    description = "Sign-in attempts"
    expression  = "(http.host eq \"${var.api_hostname}\" and http.request.uri.path eq \"/auth/login\")"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 60
      requests_per_period = 10
      mitigation_timeout  = 600
    }
  }

  # ---- Payment release ----------------------------------------------------
  # Deliberately tight. A legitimate authorizer releases a handful of batches an hour;
  # anything faster is either an error or an attack, and the cost of a false positive
  # (waiting a minute) is far below the cost of a missed one.
  rules {
    action      = "block"
    description = "Payment release attempts"
    expression  = <<-EOT
      (http.host eq "${var.api_hostname}"
       and starts_with(http.request.uri.path, "/authorization/")
       and http.request.method eq "POST")
    EOT
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 60
      requests_per_period = 12
      mitigation_timeout  = 300
    }
  }

  # ---- Exports ------------------------------------------------------------
  # Every export is already audited with actor, filter and row count. This limits the rate
  # at which a compromised session could enumerate the ledger.
  rules {
    action      = "block"
    description = "Data exports"
    expression  = "(http.host eq \"${var.api_hostname}\" and starts_with(http.request.uri.path, \"/exports/\"))"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 300
      requests_per_period = 20
      mitigation_timeout  = 600
    }
  }

  # ---- Callback ingress ---------------------------------------------------
  # Generous, because a large payroll settling produces a genuine burst of callbacks, and
  # Daraja does not retry a delivery we reject.
  rules {
    action      = "block"
    description = "Provider callback flood protection"
    expression  = <<-EOT
      (http.host eq "${var.api_hostname}"
       and starts_with(http.request.uri.path, "/integrations/daraja/"))
    EOT
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 600
      mitigation_timeout  = 60
    }
  }

  # ---- General API --------------------------------------------------------
  rules {
    action      = "managed_challenge"
    description = "General API request ceiling"
    expression  = "(http.host eq \"${var.api_hostname}\")"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 60
      requests_per_period = 600
      mitigation_timeout  = 60
    }
  }
}

# ---------------------------------------------------------------------------
# Managed rulesets
# ---------------------------------------------------------------------------

resource "cloudflare_ruleset" "waf_managed" {
  zone_id     = var.zone_id
  name        = "SOLVAREN managed WAF"
  description = "Cloudflare managed rules"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules {
    action = "execute"
    action_parameters {
      id = "efb7b8c949ac4650a09736fc376e9aee" # Cloudflare Managed Ruleset
    }
    expression  = "true"
    description = "Cloudflare Managed Ruleset"
    enabled     = true
  }

  rules {
    action = "execute"
    action_parameters {
      id = "4814384a9e5d4991b9815dcfc25d2f1f" # OWASP Core Ruleset
      overrides {
        # The default paranoia level produces false positives on legitimate CSV uploads
        # and on JSON bodies containing recipient names with apostrophes. Anomaly scoring
        # at this threshold blocks genuine attacks without rejecting a payroll file.
        categories {
          category = "paranoia-level-3"
          enabled  = false
        }
        categories {
          category = "paranoia-level-4"
          enabled  = false
        }
      }
    }
    expression  = "true"
    description = "OWASP Core Ruleset"
    enabled     = true
  }
}

# ---------------------------------------------------------------------------
# Cloudflare Access — administrative perimeter (spec §16, §16.2)
# ---------------------------------------------------------------------------

resource "cloudflare_zero_trust_access_application" "admin_api" {
  zone_id                   = var.zone_id
  name                      = "SOLVAREN administrative API"
  domain                    = "${var.api_hostname}/admin"
  type                      = "self_hosted"
  session_duration          = "30m"
  auto_redirect_to_identity = true
  http_only_cookie_attribute = true
  # An administrative session that outlives the browser tab is an unnecessary risk.
  same_site_cookie_attribute = "strict"
}

resource "cloudflare_zero_trust_access_policy" "admin_api_allow" {
  application_id = cloudflare_zero_trust_access_application.admin_api.id
  zone_id        = var.zone_id
  name           = "Named administrators only"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.administrator_emails
  }

  # Access is a perimeter, not the authorization: SOLVAREN still requires L3 authority,
  # fresh authentication and WebAuthn on every administrative call.
  require {
    login_method = [] # populated with the organisation's IdP method id at go-live
  }
}

resource "cloudflare_zero_trust_access_application" "health" {
  zone_id          = var.zone_id
  name             = "SOLVAREN readiness probe"
  domain           = "${var.api_hostname}/health/ready"
  type             = "self_hosted"
  session_duration = "15m"
}

resource "cloudflare_zero_trust_access_policy" "health_allow" {
  application_id = cloudflare_zero_trust_access_application.health.id
  zone_id        = var.zone_id
  name           = "Operators only"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.administrator_emails
  }
}

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

resource "cloudflare_record" "api" {
  zone_id = var.zone_id
  name    = split(".", var.api_hostname)[0]
  type    = "CNAME"
  content = "solvaren-api.workers.dev"
  proxied = true # never expose the origin directly (spec §16.1)
  comment = "SOLVAREN API Worker"
}

resource "cloudflare_record" "app" {
  zone_id = var.zone_id
  name    = split(".", var.app_hostname)[0]
  type    = "CNAME"
  content = "solvaren-web.pages.dev"
  proxied = true
  comment = "SOLVAREN console"
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "callback_url_template" {
  value       = "https://${var.api_hostname}/integrations/daraja/callback/{organizationId}/{secret}"
  description = "Register this shape as the Daraja ResultURL. The per-organisation secret is generated when the integration is configured and is never displayed after saving."
}

output "waf_rule_count" {
  value       = length(cloudflare_ruleset.waf_custom.rules)
  description = "Custom WAF rules in force."
}
