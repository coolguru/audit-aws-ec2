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

coreo_uni_util_jsrunner "cis124-processor" do
  action :run
  json_input '[COMPOSITE::coreo_aws_rule_runner.iam-policies-inventory-runner.report]'
  function <<-EOH
  const ruleMetaJSON = {
      'iam-policies-admin-privilege-rule': COMPOSITE::coreo_aws_rule.iam-policies-admin-privilege-rule.inputs,
  };
  const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count'];
  const ruleMeta = {};

  Object.keys(ruleMetaJSON).forEach(rule => {
      const flattenedRule = {};
      ruleMetaJSON[rule].forEach(input => {
          if (ruleInputsToKeep.includes(input.name))
              flattenedRule[input.name] = input.value;
      })
      ruleMeta[rule] = flattenedRule;
  })

  const CIS_RULE = 'iam-policies-admin-privilege-rule'
  const INVENTORY_RULE = 'iam-policies-inventory"';

  const regionArrayJSON = "['us-east-1', 'us-west-2']";
  const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'))


  const iamPoliciesInventory = json_input[0];


  const json_output = copyViolationInNewJsonInput(regionArray);

  regionArray.forEach(region => {
      if (!iamPoliciesInventory[region]) return;

      const trails = Object.keys(iamPoliciesInventory[region]);

      trails.forEach(trail => {
          json_output['number_checks'] = json_output['number_checks'] + 1;

          if (!iamPoliciesInventory[region][trail]['violations'][INVENTORY_RULE]) {
              updateOutputWithResults(region, trail, iamPoliciesInventory[region][trail]['violations'][INVENTORY_RULE], CIS_RULE);
          }
      })
  })

  function copyViolationInNewJsonInput(regions) {
      const output = {};
      output['number_ignored_violations'] = 0;
      output['number_violations'] = 0;
      output['number_checks'] = 0;
      output['violations'] = {};
      regions.forEach(regionKey => {
          output['violations'][regionKey] = {};
      });
      return output;
  }

  function updateOutputWithResults(region, vpcID, vpcDetails, rule) {
      json_output['number_violations'] = json_output['number_violations'] + 1;
      if (!json_output['violations'][region][vpcID]) {
          json_output['violations'][region][vpcID] = {};
          json_output['violations'][region][vpcID]['violator_info'] = vpcDetails;
      }
      if (!json_output['violations'][region][vpcID]['violations']) {
          json_output['violations'][region][vpcID]['violations'] = {};
      }

      json_output['violations'][region][vpcID]['violations'][rule] = Object.assign(ruleMeta[CIS_RULE]);
  }

  callback(json_output['violations']);
  EOH
end

coreo_uni_util_variables "rollup-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.cis124-rule.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis124-processor.return'}
            ])
end
