#!/bin/bash

echo "using bucket $CIS_TEST_RESULTS_BUCKET"

if [ "$CIS_TEST_RESULTS_BUCKET" = "" ]
then
	echo "must set e.v. CIS_TEST_RESULTS_BUCKET"
	exit 1
fi

aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' --query 'SecurityGroups[*].{Name:GroupName}' > cis_4_1-awscli.json

aws s3 cp cis_4_1-awscli.json s3://$CIS_TEST_RESULTS_BUCKET/cis_4_1/cis_4_1-awscli.json

aws s3 cp s3://$CIS_TEST_RESULTS_BUCKET/cis_4_1/cis_4_1-coreo.json .

node extract_data_4_1.js