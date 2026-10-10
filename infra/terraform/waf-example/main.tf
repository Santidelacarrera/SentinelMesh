# Example target for SentinelMesh dry-run plans. SentinelMesh renders HCL like this and shows `terraform plan`
# output in the approval inbox; `terraform apply` is only ever run after a signed SecOps approval.
terraform {
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}
variable "offender_cidrs" { type = list(string) default = [] }

resource "aws_wafv2_ip_set" "offenders" {
  name               = "sentinelmesh-offenders"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.offender_cidrs
}
