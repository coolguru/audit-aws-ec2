coreo_aws_rule "config-enabled-rule" do
  action :define
  service :configservice
  link ""
  include_violations_in_count false
  display_name "Ensure AWS Config is enabled in all regions (Scored)"
  description "AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources."
  category "Audit"
  suggested_action "It is recommended to enable AWS Config be enabled in all regions."
  level "Manual"
  meta_cis_id "2.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule_runner "advise-configservice" do
  rules ["config-enabled-rule"]
  action :run
  service :configservice
end
