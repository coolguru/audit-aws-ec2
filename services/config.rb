coreo_aws_rule "cloudtrail-logs-encrypted-rule" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/"
  display_name "Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)"
  suggested_action "It is recommended that CloudTrail be configured to use SSE-KMS."
  description "AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs."
  level "Warning"
  meta_cis_id "2.7"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule_runner "cis43-rule" do
  action :run
  service :cloudtrail
  rules ["cloudtrail-logs-encrypted-rule"]
end

coreo_aws_rule "cloudtrail-inventory" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "Inventory CloudTrail"
  description "Inventory CloudTrail"
  category "Inventory"
  level "Internal"
  objectives    ["trails"]
  audit_objects ["object.trail_list.name"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "object.trail_list.name"
end

coreo_aws_rule_runner "cloudtrail-inventory-runner" do
  action :run
  service :cloudtrail
  rules ["cloudtrail-inventory"]
end

coreo_uni_util_jsrunner "cis43-processor" do
  action :run
  json_input '[COMPOSITE::coreo_aws_rule_runner.cloudtrail-inventory-runner.report]'
  function <<-'EOH'
  const ruleMetaJSON = {
      'cloudtrail-logs-encrypted-rule': COMPOSITE::coreo_aws_rule.cloudtrail-logs-encrypted-rule.inputs,
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

  const CLOUDTRAIL_LOGS_ENCRYPTED_RULE = 'cloudtrail-logs-encrypted-rule'
  const CLOUDTRAIL_INVENTORY_RULE = 'cloudtrail-inventory';

  const regionArrayJSON = "['us-east-1', 'us-west-2']";
  const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'))

  const cloudTrailInventory = json_input[0];

  const json_output = copyViolationInNewJsonInput(regionArray);

  regionArray.forEach(region => {
      if (!cloudTrailInventory[region]) return;

      const trails = Object.keys(cloudTrailInventory[region]);

      trails.forEach(trail => {
          json_output['number_checks'] = json_output['number_checks'] + 1;

          if (!cloudTrailInventory[region][trail]['violations'][CLOUDTRAIL_INVENTORY_RULE] || !verifyTrailContainsKMSkey(cloudTrailInventory[region][trail]['violations'][CLOUDTRAIL_INVENTORY_RULE]['result_info'])){
                updateOutputWithResults(region, trail, cloudTrailInventory[region][trail]['violations'][CLOUDTRAIL_INVENTORY_RULE], CLOUDTRAIL_LOGS_ENCRYPTED_RULE);
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

      json_output['violations'][region][vpcID]['violations'][rule] = Object.assign(ruleMeta[CLOUDTRAIL_LOGS_ENCRYPTED_RULE]);
  }

  function verifyTrailContainsKMSkey(results) {
      let kmsKeyExist = false
      results.forEach(result => {
          if ("kms_key_id" in result['object']){
            console.log(result['object'])
            kmsKeyExist = true
          }
      })

      return kmsKeyExist;
  }


  callback(json_output['violations']);
  EOH
end

coreo_uni_util_variables "rollup-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.cis43-rule.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis43-processor.return'}
            ])
end

coreo_uni_util_notify "cis43-notify" do
  action :notify
  type 'email'
  allow_empty true
  payload 'COMPOSITE::coreo_aws_rule_runner.cis43-rule.report'
  endpoint ({
      :to => 'nandesh@cloudcoreo.com', :subject => 'PLAN::name - cis 4.3 report'
  })
end
