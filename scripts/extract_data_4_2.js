
var fs = require("fs");
var jmespath = require('jmespath');

var text_aws = fs.readFileSync("./cis_4_2-awscli.json");
var text_coreo = fs.readFileSync("./cis_4_2-coreo.json");

var aws = JSON.parse(text_aws);
var coreo = JSON.parse(text_coreo);

//console.log(coreo);

var test = coreo["us-east-1"];
//console.log(test);

var str1;

for (var i = 0; i < aws.length; i++){
    var obj = aws[i];
    for (var key in obj){
        var attrName = key;
        var attrValue = obj[key];
        str1 = str1 + attrValue + "\n";
    }
}

console.log("list of objects from AWS CLI:\n" + str1);

var jdoc = jmespath.search(coreo, "*.*.*.group_name");
//console.log(jdoc);

var str = JSON.stringify(jdoc);
str = str.replace(/\[/g, "");
str = str.replace(/\]/g, "");
str = str.replace(/,/g, "");
str = str.replace(/\"\"/g, "\n");
str = str.replace(/\"/g, "");

console.log("list of objects from CloudCoreo:\n" + str);

