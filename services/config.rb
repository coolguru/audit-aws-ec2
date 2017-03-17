coreo_aws_rule "ec2-vpc-flow-logs" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/"
  display_name "Ensure VPC flow logging is enabled in all VPCs (Scored)"
  suggested_action "VPC Flow Logs be enabled for packet 'Rejects' for VPCs."
  description "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs."
  level "Warning"
  meta_cis_id "4.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule_runner "cis43-rule" do
  action :run
  service :ec2
  rules ["ec2-vpc-flow-logs"]
end

coreo_aws_rule "vpc-inventory" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "Ensure VPC flow logging is enabled in all VPCs (Scored)"
  suggested_action "VPC Flow Logs be enabled for packet 'Rejects' for VPCs."
  description "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs."
  category "Internal"
  level "Warning"
  meta_cis_id "4.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives    ["vpcs"]
  audit_objects ["vpcs.vpc_id"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "object.vpcs.vpc_id"
end

coreo_aws_rule "flow-logs-inventory" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "VPC for checking Flow logs"
  description "VPC flow logs rules"
  category "Internal"
  suggested_action "Enable Flow Logs"
  level "Warning"
  objectives    ["vpcs"]
  objectives    ["flow_logs"]
  audit_objects ["flow_logs.resource_id"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "object.flow_logs.resource_id"
end

coreo_aws_rule_runner "vpcs-flow-logs-inventory" do
  action :run
  service :ec2
  rules ["vpc-inventory", "flow-logs-inventory"]
  regions ${AUDIT_AWS_EC2_REGIONS}
end

coreo_uni_util_jsrunner "cis43-processor" do
  action :run
  json_input '[COMPOSITE::coreo_aws_rule_runner.vpcs-flow-logs-inventory.report]'
  function <<-'EOH'
  const ruleMetaJSON = {
      'ec2-vpc-flow-logs': COMPOSITE::coreo_aws_rule.ec2-vpc-flow-logs.inputs,
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

  const VPC_FLOW_LOGS_RULE = 'ec2-vpc-flow-logs'
  const FLOW_LOGS_INVENTORY_RULE = 'flow-logs-inventory';
  const VPC_INVENTORY_RULE = 'vpc-inventory';

  const regionArrayJSON = "${AUDIT_AWS_EC2_REGIONS}";
  const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'))

  const vpcFlowLogsInventory = json_input[0];

  const json_output = copyViolationInNewJsonInput(regionArray);

  regionArray.forEach(region => {
      if (!vpcFlowLogsInventory[region]) return;

      const vpcs = Object.keys(vpcFlowLogsInventory[region]);

      vpcs.forEach(vpc => {
          json_output['number_checks'] = json_output['number_checks'] + 1;

          if (!vpcFlowLogsInventory[region][vpc]['violations'][FLOW_LOGS_INVENTORY_RULE] || !verifyActiveFlowLogs(vpcFlowLogsInventory[region][vpc]['violations'][FLOW_LOGS_INVENTORY_RULE]['result_info'])){
                updateOutputWithResults(region, vpc, vpcFlowLogsInventory[region][vpc]['violations'][VPC_INVENTORY_RULE], VPC_FLOW_LOGS_RULE);
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

      json_output['violations'][region][vpcID]['violations'][rule] = Object.assign(ruleMeta[rule]);
  }

  function verifyActiveFlowLogs(results) {
      let flowLogsActive = false
      results.forEach(result => {
          const flow_log_status = result['object']['flow_log_status'];

          if (flow_log_status === 'ACTIVE') {
              flowLogsActive = true;
          }
      })

      return flowLogsActive;
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
