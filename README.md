# aws_certificate_auditor
Check IAM server certificates being used by AWS ELBs for expiration dates and alert via DataDog

Lists all SSL enabled elbs used in account across all regions.

pulls details about used IAM certs and alerts when close to expiration, starts alerting at 45 days
