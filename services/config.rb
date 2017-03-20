coreo_aws_rule "iam-policies-admin-privilege-rule" do
  action :define
  service :user
  link "https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=67"
  include_violations_in_count false
  display_name "Ensure IAM policies that allow full '*:*' administrative privileges are not created (Scored)"
  description "IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege—that is, granting only the permissions required to perform a task."
  category "Audit"
  suggested_action "Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges."
  level "Manual"
  meta_cis_id "1.24"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule_runner "cis124-rule" do
  action :run
  service :iam
  rules ["iam-policies-admin-privilege-rule"]
end


coreo_aws_rule "iam-policies-inventory" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "Inventory CloudTrail"
  description "Inventory CloudTrail"
  category "Inventory"
  level "Internal"
  objectives    ["policies"]
  audit_objects ["object.policies.arn"]
  operators     ["=~"]
  raise_when    [/arn:aws:iam::[0-9]+/]
  id_map        "object.policies.arn"
end

coreo_aws_rule_runner "iam-policies-inventory-runner" do
  action :run
  service :iam
  rules ["iam-policies-inventory"]
end
