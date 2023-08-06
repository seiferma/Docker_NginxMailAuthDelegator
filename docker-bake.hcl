variable "VERSION" {
  default = "0.0.1"
}

group "default" {
  targets = ["default"]
}

target "default" {
  tags = ["quay.io/seiferma/nginx-mail-auth-delegator:${VERSION}", "quay.io/seiferma/nginx-mail-auth-delegator:latest"]
}
