#!/bin/bash

aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' --query 'SecurityGroups[*].{Name:GroupName}' > aws_cli.json

aws s3 cp aws_cli.json s3://cloudcoreo-cis-test-results/cis_4_1/aws_cli.json