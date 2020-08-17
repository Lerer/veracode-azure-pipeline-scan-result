import tl = require('azure-pipelines-task-lib/task');

import * as fs from 'fs';

interface Rule  {
    id: string,
    shortDescription: {
        text: string
    },
    helpUri: string,
    properties: {
        category: string,
        tags: string[]
    },
    defaultConfiguration: {
        level: string
    }
}

let replacer :{regex:any,value:string}[] = [];
let levels:any  = {};

export const setupSourceReplacement = (sub1:string|undefined,sub2:string|undefined,sub3:string|undefined) => {
    if (sub1!=undefined && sub1.length>0) {
        _parseReplacer(sub1);
        if (sub2!=undefined && sub2.length>0) {
            _parseReplacer(sub2);
            if (sub3!=undefined && sub3.length>0) {
                _parseReplacer(sub3);
            }
        }
    }
}

const _parseReplacer = (input:string) => {
    const values = input.split(':');
    if (values.length!=2) {
        throw new Error('source-base-path attrbute in wrong format. Please refer to the action documentation');
    }
    const regEx = RegExp(values[0]);
    replacer.push({
        regex: regEx,
        value: values[1]
    })
}

export const sliceReportLevels = (requestedLevels:string) =>  {
    try {
        const split = requestedLevels.split(':');
        if (split===undefined || split.length!=3){
            throw new Error("'finding-rule-level' should have 3 integer values seporated with ':' and no white spaces");
        }
        let vl = 5;
        let gl = 'error';
        let split_loc = 0;
        let split_value = parseInt(split[split_loc]);
        while (vl>=0){
            if (vl>=split_value){
                levels[""+vl] = gl;
                vl--;
            } else {
                split_loc++;
                if (split_loc==3) {
                    return;
                }
                split_value = parseInt(split[split_loc]);
                if (gl === 'error'){
                    gl = 'warning';
                } else {
                    gl = 'note';
                }
            }
        }
    } catch (e){
        console.log(e);
        throw new Error("See documentation for valid valuse for 'finding-rule-level'");
    }
}

// none,note,warning,error
const sevIntToStr = ((sevInt:string) => {
    return levels[sevInt];
})

const addRuleToRules = (issue:any,rules:Rule[]) => {
    if (rules.filter((ruleItem:any) => ruleItem.id===issue.CWEId).length>0) {
        return null;
    }
    /*
     {
              "id": "no-unused-vars",
              "shortDescription": {
                "text": "disallow unused variables"
              },
              "helpUri": "https://eslint.org/docs/rules/no-unused-vars",
              "properties": {
                "category": "Variables"
              }
            }
    */
    let rule: Rule = {
        id: issue.CWEId,
        shortDescription: {
            text: "CWE-"+issue.CWEId+": "+issue.IssueType
        },
        helpUri:  "https://cwe.mitre.org/data/definitions/"+issue.CWEId+".html",
        properties: {
            category: issue.IssueTypeId,
            tags: [issue.IssueTypeId]
        },
        defaultConfiguration: {
            level: sevIntToStr(issue.Severity)
        }
    }

    return rule;
}

const getFilePath = (filePath:string) => {
    let final:string = filePath;
    replacer.forEach(element => {
        if (element.regex.test(final)){
            final = final.replace(element.regex,element.value);
        }
    });
    return final;
}

/*
 {
    "Title": "java.sql.Statement.executeQuery",
    "IssueId": "1016",
    "GOB": "B",
    "Severity": "4",
    "IssueTypeId": "taint",
    "IssueType": "Improper Neutralization of Special Elements used in an SQL Command (\u0027SQL Injection\u0027)",
    "CWEId": "89",
    "VCId": "89.005",
    "DisplayText": "\u003cspan\u003eThis database query contains a SQL injection flaw.  The call to java.sql.Statement.executeQuery() constructs a dynamic SQL query using a variable derived from untrusted input.  An attacker could exploit this flaw to execute arbitrary SQL queries against the database. The first argument to executeQuery() contains tainted data from the variable sqlQuery. The tainted data originated from an earlier call to AnnotationVirtualController.vc_annotation_entry.\u003c/span\u003e \u003cspan\u003eAvoid dynamically constructing SQL queries.  Instead, use parameterized prepared statements to prevent the database from interpreting the contents of bind variables as part of the query.  Always validate untrusted input to ensure that it conforms to the expected format, using centralized data validation routines when possible.\u003c/span\u003e \u003cspan\u003eReferences: \u003ca href\u003d\"https://cwe.mitre.org/data/definitions/89.html\"\u003eCWE\u003c/a\u003e \u003ca href\u003d\"https://www.owasp.org/index.php/SQL_injection\"\u003eOWASP\u003c/a\u003e \u003ca href\u003d\"https://webappsec.pbworks.com/SQL-Injection\"\u003eWASC\u003c/a\u003e\u003c/span\u003e",
    "Files": {
        "SourceFile": {
        "File": "com/veracode/verademo/controller/UserController.java",
        "Line": "166",
        "FunctionName": "processLogin",
        "QualifiedFunctionName": "com.veracode.verademo.controller.UserController.processLogin",
        "FunctionPrototype": "java.lang.String processLogin(java.lang.String, java.lang.String, java.lang.String, java.lang.String, org.springframework.ui.Model, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)",
        "Scope": "com.veracode.verademo.controller.UserController"
        }
    },
    "FlawMatch": {
        "ProcedureHash": "844194490",
        "PrototypeHash": "839857025",
        "FlawHash": "3392777041",
        "FlawHashCount": "1",
        "FlawHashOrdinal": "1",
        "CauseHash": "1176028798",
        "CauseHashCount": "1",
        "CauseHashOrdinal": "1"
    }
    },
*/
export const convertPipelineResultFileToSarifFile = (inputFileName:string,outputFileName:string) => {
    var results:any = {};

    let rawdata = fs.readFileSync(inputFileName);
    results = JSON.parse(rawdata.toString());
    console.log('Pipeline Scan results file found and parsed - validated JSON file');

    //"scan_status": "SUCCESS"
    if (results.scan_status==='SUCCESS') {
        let issues = results.results.TestResults.Issues.Issue;
        console.log('Issues count: '+issues.length);

        let rules:Rule[]=[];

        // convert to SARIF json
        let sarifResults = issues.map((issue:any) => {
            // append rule to ruleset - if not already there
            let rule: Rule|null = addRuleToRules(issue,rules);
            if (rule!==null){
                rules.push(rule);
            }

            // construct flaw location
            const issueFileLocation = issue.Files.SourceFile;
            const filePath = getFilePath(issueFileLocation.File);
            let location = {
                physicalLocation: {
                    artifactLocation: {
                        uri: filePath
                    },
                    region: {
                        startLine: parseInt(issueFileLocation.Line)
                    }
                }
            }
            // get the severity number to name
            let serStr = sevIntToStr(issue.Severity);
            // construct the issue
            let resultItem = {
                level: serStr,
                message: {
                    text: issue.DisplayText,
                },
                locations: [location],
                ruleId: issue.CWEId
            }
            return resultItem;
        });

        // construct the full SARIF content
        let sarifFileJSONContent = {
            $schema : "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version : "2.1.0",
            runs : [
                {
                    tool : {
                        driver : {
                            name : "Veracode Pipeline Scanner",
                            rules: rules
                        }
                    },
                    results: sarifResults
                }   
            ]
        };

        // save to file
        fs.writeFileSync(outputFileName,JSON.stringify(sarifFileJSONContent));
        console.log('SARIF file created: '+outputFileName);
    }
}
