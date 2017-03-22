
coreo_aws_rule "ec2-inventory-instances" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-inventory.html"
  include_violations_in_count false
  display_name "EC2 Instance Inventory"
  description "This rule performs an inventory on all EC2 instances in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.instance_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.reservation_set.instances_set.instance_id"
end

coreo_aws_rule "ec2-inventory-security-groups" do
  action :define
  service :ec2
  # link "http://kb.cloudcoreo.com/mydoc_ec2-inventory.html"
  include_violations_in_count false
  display_name "EC2 Security Group Inventory"
  description "This rule performs an inventory on all EC2 Security Groups in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["security_groups"]
  audit_objects ["object.security_group_info.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-ip-address-whitelisted" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-ip-address-whitelisted.html"
  display_name "Security Group contains IP address"
  description "Security Group contains IP address"
  category "Security"
  suggested_action "Review Security Group to ensure that the host ip address added is to allowed access."
  level "Warning"
  objectives ["security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["=~"]
  raise_when [/\/32/]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-unrestricted-traffic" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-unrestricted-traffic.html"
  display_name "Security group allows unrestricted traffic"
  description "All IP addresses are allowed to access resources in a specific security group."
  category "Security"
  suggested_action "Restrict access to the minimum specific set of IP address or ports necessary."
  level "Warning"
  objectives ["security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["=="]
  raise_when ["0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-1521-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 1521"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 1521, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-3306-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 3306"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 3306, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-5432-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 5432"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 5432, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-27017-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 27017"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 27017, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-1433-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 1433"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 1433, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-3389-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 3389"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  meta_cis_id "4.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 3389, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-22-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 22"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  meta_cis_id "4.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 22, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-5439-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 5439"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 5439, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-23" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 23"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port"]
  operators ["==","=="]
  raise_when ["tcp", 23]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-21" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 21"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port"]
  operators ["==","=="]
  raise_when ["tcp", 21]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-20" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 20"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port"]
  operators ["==","=="]
  raise_when ["tcp", 20]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-ports-range" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-ports-range.html"
  display_name "Security group contains a port range"
  description "Security group contains a port range rather than individual ports."
  category "Security"
  suggested_action "Only add rules to your Security group that specify individual ports and don't use port ranges unless they are required."
  level "Warning"
  objectives ["security_groups"]
  audit_objects ["security_group_info.ip_permissions.from_port"]
  operators ["!="]
  raise_when ["object[:to_port]"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-not-used-security-groups" do
  action :define
  service :ec2
  display_name "EC2 security group is not used"
  description "Security group is not used anywhere"
  category "Security"
  suggested_action "Remove this security group"
  level "Warning"
  objectives ["security_groups", "security_groups"]
  audit_objects ["security_group_info", "group_name"]
  operators ["==", "!~"]
  raise_when [false, /^default$/]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-security-groups-list" do
  action :define
  service :ec2
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["security_groups"]
  audit_objects ["security_group_info.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-instances-active-security-groups-list" do
  action :define
  service :ec2
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.group_set.group_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.reservation_set.instances_set.instance_id"
end

coreo_aws_rule "elb-load-balancers-active-security-groups-list" do
  action :define
  service :elb
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.security_groups"]
  operators ["=~"]
  raise_when [//]
  id_map "object.load_balancer_descriptions.load_balancer_name"
end

coreo_aws_rule "ec2-vpc-flow-logs-cis-4.3" do
  action :define
  service :user
  category "Audit"
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=136"
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

coreo_aws_rule "vpc-inventory" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "Ensure VPC flow logging is enabled in all VPCs (Scored)"
  suggested_action "VPC Flow Logs be enabled for packet 'Rejects' for VPCs."
  description "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs."
  category "Audit"
  level "Internal"
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
  action ${AUDIT_AWS_EC2_ALERT_LIST}.include? 'ec2-vpc-flow-logs-cis-4.3' ? :run : :nothing
  service :ec2
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "VPC for checking Flow logs"
  description "VPC flow logs rules"
  category "Audit"
  suggested_action "Enable Flow Logs"
  level "Internal"
  objectives    ["vpcs"]
  objectives    ["flow_logs"]
  audit_objects ["flow_logs.resource_id"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "object.flow_logs.resource_id"
end

coreo_aws_rule_runner "vpcs-flow-logs-inventory" do
  action ${AUDIT_AWS_EC2_ALERT_LIST}.include? 'ec2-vpc-flow-logs-cis-4.3' ? :run : :nothing
  service :ec2
  regions ["us-east-1"]
  rules ["vpc-inventory", "flow-logs-inventory"]
end

coreo_uni_util_variables "ec2-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.number_violations' => 'unset'}
            ])
end

coreo_aws_rule_runner_ec2 "advise-ec2" do
  action :run
  rules ${AUDIT_AWS_EC2_ALERT_LIST}
  regions ${AUDIT_AWS_EC2_REGIONS}
end

coreo_aws_rule_runner_ec2 "advise-unused-security-groups-ec2" do
  action :run
  rules ["ec2-security-groups-list", "ec2-instances-active-security-groups-list"]
  regions ${AUDIT_AWS_EC2_REGIONS}
end

coreo_aws_rule_runner_elb "advise-elb-ec2" do
  action :run
  rules ['elb-load-balancers-active-security-groups-list']
  regions ${AUDIT_AWS_EC2_REGIONS}
end


coreo_uni_util_jsrunner "security-groups-ec2" do
  action :run
  json_input '{
      "main_report":COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report,
      "number_violations":COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.number_violations,
      "ec2_report":COMPOSITE::coreo_aws_rule_runner_ec2.advise-unused-security-groups-ec2.report,
      "elb_report":COMPOSITE::coreo_aws_rule_runner_elb.advise-elb-ec2.report
  }'
  function <<-EOH

const ec2_alerts_list = ${AUDIT_AWS_EC2_ALERT_LIST};
if(!ec2_alerts_list.includes('ec2-not-used-security-groups')) {
  coreoExport('number_violations', JSON.stringify(COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.number_violations));
  callback(json_input.main_report);
  return;
}

const activeSecurityGroups = [];

const groupIsActive = (groupId) => {
    for (let activeGroupId of activeSecurityGroups) {
        if (activeGroupId === groupId) return true;
    }
    return false;
};

Object.keys(json_input.elb_report).forEach((region) => {
  Object.keys(json_input.elb_report[region]).forEach(key => {
      const violation = json_input.elb_report[region][key].violations['elb-load-balancers-active-security-groups-list'];
      if (!violation) return;
      violation.result_info.forEach((obj) => {
          obj.object.forEach((secGroup) => {
              activeSecurityGroups.push(secGroup);
          })
      });
  });
});
Object.keys(json_input.ec2_report).forEach((region) => {

  Object.keys(json_input.ec2_report[region]).forEach(key => {
      const violation = json_input.ec2_report[region][key].violations['ec2-instances-active-security-groups-list'];
      if (!violation) return;
      violation.result_info.forEach((obj) => {
          activeSecurityGroups.push(obj.object.group_id);
      });
  });
});
let number_violations = 0;
if(json_input['number_violations']) {
  number_violations = parseInt(json_input['number_violations']);
}
Object.keys(json_input.ec2_report).forEach((region) => {
  Object.keys(json_input.ec2_report[region]).forEach(key => {
      const tags = json_input.ec2_report[region][key].tags;
      const violations = json_input.ec2_report[region][key].violations["ec2-security-groups-list"];
      if (!violations) return;

      const currentSecGroup = violations['result_info'][0].object;
      if (groupIsActive(currentSecGroup.group_id)) return;
      const securityGroupIsNotUsedAlert = {
          'display_name': 'EC2 security group is not used',
          'description': 'Security group is not used anywhere',
          'category': 'Audit',
          'suggested_action': 'Remove this security group',
          'level': 'Warning',
          'region': violations.region
      };
      number_violations++
      const violationKey = 'ec2-not-used-security-groups';
      //console.log("working on key: " + key + " in region: " + region);
      if (!json_input.main_report[region]) {
          json_input.main_report[region] = {};
      }
      if (!json_input.main_report[region][key]) {
          json_input.main_report[region][key] = { violations: {}, tags: [] };
      }
      json_input.main_report[region][key].violations[violationKey] = securityGroupIsNotUsedAlert;
      json_input.main_report[region][key].tags.concat(tags);
  });
});


coreoExport('number_violations', JSON.stringify(number_violations));

callback(json_input.main_report);
  EOH
end

coreo_uni_util_variables "ec2-update-planwide-2" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.security-groups-ec2.return'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.security-groups-ec2.return'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.number_violations' => 'COMPOSITE::coreo_uni_util_jsrunner.security-groups-ec2.number_violations'}
            ])
end


coreo_uni_util_jsrunner "cis43-processor" do
  action ${AUDIT_AWS_EC2_ALERT_LIST}.include? 'ec2-vpc-flow-logs-cis-4.3' ? :run : :nothing
  json_input '[COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report, COMPOSITE::coreo_aws_rule_runner.vpcs-flow-logs-inventory.report]'
  function <<-'EOH'
  const ruleMetaJSON = {
      'ec2-vpc-flow-logs-cis-4.3': COMPOSITE::coreo_aws_rule.ec2-vpc-flow-logs-cis-4.3.inputs,
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

  const VPC_FLOW_LOGS_RULE = 'ec2-vpc-flow-logs-cis-4.3'
  const FLOW_LOGS_INVENTORY_RULE = 'flow-logs-inventory';
  const VPC_INVENTORY_RULE = 'vpc-inventory';

  const regionArrayJSON = "${AUDIT_AWS_EC2_REGIONS}";
  const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'))

  const vpcFlowLogsInventory = json_input[1];
  var json_output = json_input[0]

  const violations = copyViolationInNewJsonInput(regionArray, json_input[0]);

  regionArray.forEach(region => {
      if (!vpcFlowLogsInventory[region]) return;

      const vpcs = Object.keys(vpcFlowLogsInventory[region]);

      vpcs.forEach(vpc => {
          violations['number_checks'] = violations['number_checks'] + 1;

          if (!vpcFlowLogsInventory[region][vpc]['violations'][FLOW_LOGS_INVENTORY_RULE] || !verifyActiveFlowLogs(vpcFlowLogsInventory[region][vpc]['violations'][FLOW_LOGS_INVENTORY_RULE]['result_info'])) {
                updateOutputWithResults(region, vpc, vpcFlowLogsInventory[region][vpc]['violations'][VPC_INVENTORY_RULE], VPC_FLOW_LOGS_RULE);
          }
      })
  })

  function copyViolationInNewJsonInput(regions, input) {
      const output = {};
      regions.forEach(regionKey => {
          if (!input[regionKey]) {
            output[regionKey] = {};
          } else {
            output[regionKey] = input[regionKey]
          }
      });
      return output;
  }

  function updateOutputWithResults(region, vpcID, vpcDetails, rule) {
      if (!violations[region][vpcID]) {
          violations[region][vpcID] = {};
          violations[region][vpcID]['violator_info'] = vpcDetails;
      }
      if (!violations[region][vpcID]['violations']) {
          violations[region][vpcID]['violations'] = {};
      }

      violations[region][vpcID]['violations'][rule] = Object.assign(ruleMeta[rule]);
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

  callback(json_output);
  EOH
end

coreo_uni_util_variables "ec2-update-planwide-3" do
  action :${AUDIT_AWS_EC2_ALERT_LIST}.include? 'ec2-vpc-flow-logs-cis-4.3' ? :set : :nothing
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis43-processor.return'}
            ])
end

coreo_uni_util_jsrunner "ec2-tags-to-notifiers-array" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-9"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report}'
  function <<-EOH

function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log(`Error reading suppression.yaml file`);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log(`Error reading table.yaml file`);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));

  let alertListToJSON = "${AUDIT_AWS_EC2_ALERT_LIST}";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}


setTableAndSuppression();

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;


const SETTINGS = { NO_OWNER_EMAIL, OWNER_TAG,
    ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditEC2 = new CloudCoreoJSRunner(JSON_INPUT, SETTINGS);

const newJsonInput = AuditEC2.getSortedJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(newJsonInput));
coreoExport('report', JSON.stringify(newJsonInput['violations']));

const letters = AuditEC2.getLetters();
callback(letters);
  EOH
end



coreo_uni_util_variables "ec2-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.report'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.JSONReport'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.table'}
            ])
end

coreo_uni_util_jsrunner "ec2-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-ec2-to-tag-values" do
  action((("${AUDIT_AWS_EC2_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-ec2-rollup" do
  action((("${AUDIT_AWS_EC2_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_EC2_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty true
  send_on '${AUDIT_AWS_EC2_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 rule results on PLAN::stack_name :: PLAN::name'
  })
end
