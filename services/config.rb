coreo_aws_rule "s3-cloudtrail-public-access" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/"
  display_name "Ensure S3 bucket for CloudTrail logs not publicly accessible"
  suggested_action "Remove any public access that has been granted to CloudTrail buckets"
  description "Access controls (ACLs) to CloudTrail S3 logging buckets allow public access"
  level "Warning"
  meta_cis_id "2.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "s3-cloudtrail-no-logging" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/"
  display_name "Ensure S3 bucket logging is enabled for CloudTrail logs"
  suggested_action "S3 Bucket access logging be enabled on the CloudTrail S3 bucket"
  description "Logging of CloudTrail S3 bucket is not configured"
  level "Warning"
  meta_cis_id "2.6"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule_runner "cis2-rules" do
  action :run
  service :cloudtrail
  rules ["s3-cloudtrail-public-access", "s3-cloudtrail-no-logging"]
end

coreo_aws_rule "bucket-acl-inventory" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "Bucket ACL for CloudTrail trail"
  description "Bucket matches rules"
  category "Dataloss"
  suggested_action "Modify the bucket ACL"
  level "Emergency"
  objectives    ["bucket_acl"]
  audit_objects ["grants.grantee.uri"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "modifiers.bucket"
end

coreo_aws_rule "bucket-logging-inventory" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "Bucket Logging for CloudTrail trail"
  description "Bucket matches rules"
  category "Dataloss"
  suggested_action "Modify the bucket logging"
  level "Emergency"
  objectives    ["bucket_logging"]
  audit_objects ["logging_enabled.target_bucket"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "modifiers.bucket"
end

coreo_aws_rule_runner "bucket-inventory" do
  service :s3
  action :run
  rules ["bucket-logging-inventory", "bucket-acl-inventory"]
  global_objective "buckets"
  global_modifier({:bucket => "buckets.name"})
end

coreo_aws_rule "cloudtrail-inventory" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc-inventory.html"
  include_violations_in_count false
  display_name "Cloudtrail Inventory"
  description "This rule performs an inventory on all trails in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  meta_cis_id "99.999"
  objectives ["trails"]
  audit_objects ["object.trail_list.name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.trail_list.name"
end

coreo_aws_rule_runner "cloudtrail-inventory" do
  action :run
  service :cloudtrail
  rules ["cloudtrail-inventory"]
end

coreo_uni_util_jsrunner "cis2-processor" do
  action :run
  json_input '[COMPOSITE::coreo_aws_rule_runner.bucket-inventory.report, COMPOSITE::coreo_aws_rule_runner.cloudtrail-inventory.report]'
  function <<-'EOH'
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

function updateOutputWithResults(region, bucket, result, targetRule, sourceRule) {
    json_output['number_violations'] = json_output['number_violations'] + 1;
    if (!json_output['violations'][region][bucket]) {
        json_output['violations'][region][bucket] = {};
        json_output['violations'][region][bucket]['violator_info'] = result['violator_info'];
    }
    if (!json_output['violations'][region][bucket]['violations']) {
        json_output['violations'][region][bucket]['violations'] = {};
    }
    if (!json_output['violations'][region][bucket]['tags']) {
        json_output['violations'][region][bucket]['tags'] = result['tags'];
    }

    json_output['violations'][region][bucket]['violations'][targetRule] = Object.assign(ruleMeta[targetRule]);
    json_output['violations'][region][bucket]['violations'][targetRule]['region'] = region;

    if (result['violations'][sourceRule]) {
        // Overwrite region if defined in violation because of S3 bucket locations
        json_output['violations'][region][bucket]['violations'][targetRule]['region'] = result['violations'][sourceRule]['region'];
        json_output['violations'][region][bucket]['violations'][targetRule]['result_info'] = result['violations'][sourceRule]['result_info'];
    }
}

const CLOUDTRAIL_INVENTORY_RULE = 'cloudtrail-inventory';
const S3_ACL_INVENTORY_RULE = 'bucket-acl-inventory';
const S3_LOGGING_INVENTORY_RULE = 'bucket-logging-inventory';
const VIOLATING_GRANTEE_URIS = [
    'http://acs.amazonaws.com/groups/global/AllUsers',
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
];

const ruleMetaJSON = {
    's3-cloudtrail-public-access': COMPOSITE::coreo_aws_rule.s3-cloudtrail-public-access.inputs,
    's3-cloudtrail-no-logging': COMPOSITE::coreo_aws_rule.s3-cloudtrail-no-logging.inputs
};
const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count'];
const ruleMeta = {};
Object.keys(ruleMetaJSON).forEach(rule => {
    const flattenedRule = {};
    ruleMetaJSON[rule].forEach(input => {
        if (ruleInputsToKeep.includes(input.name)) flattenedRule[input.name] = input.value;
    })
    ruleMeta[rule] = flattenedRule;
})

const rulesArrayJSON = "['s3-cloudtrail-public-access', 's3-cloudtrail-no-logging']";
const regionArrayJSON = "['us-east-1', 'us-west-2']";
const rulesArray = JSON.parse(rulesArrayJSON.replace(/'/g, '"'));
const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'));

const s3BucketInventory = json_input[0];
const cloudtrail = json_input[1];

const json_output = copyViolationInNewJsonInput(regionArray);

const trailsToCheck = [];
regionArray.forEach(region => {
    console.log(`------ Checking region: ${region}`);
    // There can be no violations without trails
    if (!cloudtrail[region]) return;

    const trails = Object.keys(cloudtrail[region]);
    trails.forEach(trail => {
        const results = cloudtrail[region][trail]['violations'][CLOUDTRAIL_INVENTORY_RULE]['result_info'];
        results.forEach(result => {
            const bucket = result['object']['s3_bucket_name'];
            if (bucket) {
                trailsToCheck.push(bucket);
                console.log(`Found cloudtrail bucket: ${bucket}`);
            }
        })
    })
})

regionArray.forEach(region => {
    if (!s3BucketInventory[region]) return;
    const buckets = Object.keys(s3BucketInventory[region]);
    buckets.forEach(bucket => {
        if (trailsToCheck.includes(bucket)) {
            console.log(`Found bucket against which to check rules: ${bucket}`);

            let targetRule = 's3-cloudtrail-public-access';
            if (rulesArray.includes(targetRule)) {
                // Need to check grantee URIs against list of violating URIs
                let haveACLViolation = false;
                if (s3BucketInventory[region][bucket]['violations'][S3_ACL_INVENTORY_RULE]) {
                    const bucketACLResults = s3BucketInventory[region][bucket]['violations'][S3_ACL_INVENTORY_RULE]['result_info'];
                    bucketACLResults.forEach(result => {
                        json_output['number_checks'] = json_output['number_checks'] + 1;
                        const granteeURI = result['object']['uri'];
                        if (VIOLATING_GRANTEE_URIS.includes(granteeURI)) {
                            // Have violation
                            console.log(`Have violation for ${bucket} with Grantee URI: ${granteeURI}`);
                            haveACLViolation = true;
                        } else {
                            console.log(`Passed audit for ${bucket} with Grantee URI: ${granteeURI}`);
                        }
                    })
                    if (haveACLViolation) {
                        const sourceRule = S3_ACL_INVENTORY_RULE;
                        updateOutputWithResults(region, bucket, s3BucketInventory[region][bucket], targetRule, sourceRule);
                    }
                }
            }

            targetRule = 's3-cloudtrail-no-logging';
            if (rulesArray.includes(targetRule)) {
                let haveLoggingViolation = false;
                if (s3BucketInventory[region][bucket]['violations'][S3_LOGGING_INVENTORY_RULE]) {
                    const bucketLoggingResults = s3BucketInventory[region][bucket]['violations'][S3_LOGGING_INVENTORY_RULE]['result_info'];
                    bucketLoggingResults.forEach(result => {
                        json_output['number_checks'] = json_output['number_checks'] + 1;
                        const targetBucket = result['object']['target_bucket'];
                        if (targetBucket) {
                            console.log(`Passed audit for ${bucket} with Logging Enabled to bucket: ${targetBucket}`);
                        } else {
                            haveLoggingViolation = true;
                        }
                    })
                } else {
                    haveLoggingViolation = true;
                    json_output['number_checks'] = json_output['number_checks'] + 1;
                }
                if (haveLoggingViolation) {
                    console.log(`Have violation for ${bucket} with Logging disabled`);
                    const sourceRule = S3_LOGGING_INVENTORY_RULE;
                    updateOutputWithResults(region, bucket, s3BucketInventory[region][bucket], targetRule, sourceRule);
                }
            }
        } else {
            // No grantee.uri for the bucket means we've passed
            console.log(`Bucket not used for CloudTrail: ${bucket}`);
        }
    })
})
callback(json_output['violations']);
EOH
end

coreo_uni_util_notify "multi-jsrunner-file" do
  action :notify
  type 'email'
  allow_empty true
  payload_type "text"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.cis2-processor.jsrunner_file'
  endpoint ({
      :to => 'david@cloudcoreo.com', :subject => 'jsrunner file for cloudtrail-bucketlist'
  })
end

coreo_uni_util_variables "rollup-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.cis2-rules.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis2-processor.return'}
            ])
end

coreo_uni_util_notify "cis2-notify" do
  action :notify
  type 'email'
  allow_empty true
  payload 'COMPOSITE::coreo_aws_rule_runner.cis2-rules.report'
  endpoint ({
      :to => 'david@cloudcoreo.com', :subject => 'PLAN::name - cis 2.3 / 2.6 report'
  })
end
