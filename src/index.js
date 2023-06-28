const fs = require('fs');
const JiraClient = require('jira-client');
const core = require('@actions/core');

// Install jira-client
core.startGroup('Installing jira-client');
const installJiraClient = require('child_process').spawnSync('npm', ['install', 'jira-client'], { stdio: 'inherit' });
core.endGroup();

// Install @actions/core
core.startGroup('Installing @actions/core');
const installActionsCore = require('child_process').spawnSync('npm', ['install', '@actions/core'], { stdio: 'inherit' });
core.endGroup();

try {
  const jira = new JiraClient({
    protocol: 'https',
    host: core.getInput('jira-host'),
    username: core.getInput('jira-username'),
    password: core.getInput('jira-token'),
    apiVersion: '2',
    strictSSL: true,
  });

  const scanType = core.getInput('scan-type');
  if (scanType === 'zap') {
    // Parse the JSON file from Zap scan
    function parseZapOutput(jsonData) {
      let vulnerabilities = [];
      if (jsonData) {
        try {
          const data = JSON.parse(jsonData);
          for (const site of data.site) {
            for (const alert of site.alerts) {
              let instanceDescription = '\nInstances:\n';
              for (const instance of alert.instances) {
                const { uri, method, param, attack, evidence, otherinfo } = instance;
                instanceDescription += `URI: ${uri}\nMethod: ${method}\nParam: ${param}\nAttack: ${attack}\nEvidence: ${evidence}\nOtherInfo: ${otherinfo}\n\n`;
              }
              if (alert.riskcode >= parseInt(core.getInput('zap-risk-code'))) {
                vulnerabilities.push({
                  name: alert.name.concat(': ', data.site[0]['@host']).replace(/-/g, ''),
                  solution: alert.solution.replace(/<\/?p>/g, ''),
                  desc: alert.desc.concat('\n\nSolution:\n', alert.solution).replace(/<\/?p>/g, ''),
                  instanceDesc: instanceDescription
                });
              }
            }
          }
        } catch (error) {
          console.error('Error parsing Zap output:', error);
        }
      }
      console.log(vulnerabilities);
      return vulnerabilities;
    }

    async function createJiraTicket(vulnerability) {
      let jqlQuery = `project = "${core.getInput('jira-project-key')}" AND summary ~ "${vulnerability.name}" AND created >= startOfDay("-60d") AND status NOT IN ("Closed")`;
      let searchResult = await jira.searchJira(jqlQuery);

      if (!searchResult.issues || searchResult.issues.length === 0) {
        const customFieldKeyValue = process.env.JIRA_CUSTOM_FIELD_KEY_VALUE ? JSON.parse(process.env.JIRA_CUSTOM_FIELD_KEY_VALUE) : null;
        const customJiraFields = customFieldKeyValue ? { ...customFieldKeyValue } : null;
        const issue = {
          fields: {
            project: {
              key: core.getInput('jira-project-key'),
            },
            summary: core.getInput('jira-title-prefix').concat(' ', vulnerability.name),
            description: vulnerability.desc.concat('\n', vulnerability.instanceDesc),
            issuetype: {
              name: core.getInput('jira-issue-type'),
            },
            labels: core.getInput('jira-labels').split(','),
            ...(customJiraFields && Object.keys(customJiraFields).length > 0 && { ...customJiraFields }),
          },
        };

        const issueResponse = await jira.addNewIssue(issue);
        console.log(`Jira ticket created for vulnerability: ${vulnerability.name}`);

        process.env.SCAN_OUTPUT_FILE_PATH = core.getInput('scan-output-path');
        const scanOutputFilePath = process.env.SCAN_OUTPUT_FILE_PATH;

        try {
          // Use the addAttachmentOnIssue method from the Jira library
          await jira.addAttachmentOnIssue(issueResponse.key, fs.createReadStream(scanOutputFilePath));
          console.log(`Jira ticket ${issueResponse.key} created successfully.`);
        } catch (error) {
          console.error(`Error adding attachment to Jira ticket ${issueResponse.key}:`, error);
        }
        return issueResponse;
      } else {
        console.log(`Active Jira ticket already exists for vulnerability: ${vulnerability.name}`);
      }
    }

    (async () => {
      const scanOutputFilePath = core.getInput('scan-output-path');
      const jsonData = fs.readFileSync(scanOutputFilePath, 'utf-8');

      const vulnerabilities = parseZapOutput(jsonData);
      console.log(`Parsed vulnerabilities: ${vulnerabilities.length}`);

      const uniqueVulnerabilities = Array.from(new Set(vulnerabilities.map(v => v.name)))
        .map(name => {
          return vulnerabilities.find(v => v.name === name);
        });

      for (const vulnerability of uniqueVulnerabilities) {
        try {
          console.log(`Creating Jira ticket for vulnerability: ${vulnerability.name}`);
          const resp = await createJiraTicket(vulnerability);
          console.log(resp);
        } catch (error) {
          console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.name}:`, error);
        }
      }
    })();
  } else if (scanType === 'snyk') {
    function parseSnykOutput(inputData) {
      let vulnerabilities = [];
      if (inputData) {
        try {
          const data = JSON.parse(inputData);
          for (const project of Object.values(data)) {
            vulnerabilities = vulnerabilities.concat(project.vulnerabilities);
          }
        } catch (error) {
          console.error('Error parsing Snyk output:', error);
          vulnerabilities = parseNonJsonData(inputData);
        }
      }

      return vulnerabilities;
    }


    function parseNonJsonData(inputData) {
      let vulnerabilities = [];

      // Custom logic to parse non-JSON inputData
      const defaultTitle = 'Vulnerability Detected';

      vulnerabilities.push({
        title: defaultTitle,
        description: `Non-JSON output from Snyk:\n\n${inputData}`
      });

      return vulnerabilities;
    }


    async function createJiraTicket(vulnerability) {
      // JQL query with relative date math, status conditions.
      const title = vulnerability.title.replaceAll("\"", "\\\"");
      let jqlQuery = `project = "${core.getInput('jira-project-key')}" AND summary ~ "${vulnerability.title}" AND created >= startOfDay("-60d") AND status NOT IN ("Closed", "Cancelled")`;
      let searchResult = await jira.searchJira(jqlQuery);

      if (!searchResult.issues || searchResult.issues.length === 0) {
        const customFieldKeyValue = process.env.JIRA_CUSTOM_FIELD_KEY_VALUE ? JSON.parse(process.env.JIRA_CUSTOM_FIELD_KEY_VALUE) : null;
        const customJiraFields = customFieldKeyValue ? { ...customFieldKeyValue } : null;

        const issue = {
          fields: {
            project: {
              key: core.getInput('jira-project-key'),
            },
            summary: `${core.getInput('jira-title-prefix')}  ${vulnerability.title}`,
            description: vulnerability.description,
            issuetype: {
              name: core.getInput('jira-issue-type'),
            },
            labels: core.getInput('jira-labels').split(','),
            ...(customJiraFields && Object.keys(customJiraFields).length > 0 && { ...customJiraFields }),
          },
        };

        const issueResponse = await jira.addNewIssue(issue);
        console.log(`Jira ticket created for vulnerability: ${vulnerability.title}`);

        process.env.SCAN_OUTPUT_FILE_PATH = core.getInput('scan-output-path');
        const scanOutputFilePath = process.env.SCAN_OUTPUT_FILE_PATH
        try {
          // Use the addAttachmentOnIssue method from Jira library
          await jira.addAttachmentOnIssue(issueResponse.key, fs.createReadStream(scanOutputFilePath));
          console.log(`Jira ticket ${issueResponse.key} created successfully.`);
        } catch (error) {
          console.error(`Error adding attachment to Jira ticket ${issueResponse.key}:`, error);
        }
        return issueResponse;
      } else {
        console.log(`Active Jira ticket already exists for vulnerability: ${vulnerability.title}`);
      }
    }

    (async () => {
      const scanOutputFilePath = core.getInput('scan-output-path');
      const jsonData = fs.readFileSync(scanOutputFilePath, 'utf-8');

      const vulnerabilities = parseSnykOutput(jsonData);
      console.log(`Parsed vulnerabilities: ${vulnerabilities.length}`);

      const uniqueVulnerabilities = vulnerabilities
        .filter(v => v && v.title) // Filter out undefined or objects without a title
        .map(v => v.title);

      for (const vulnerability of uniqueVulnerabilities) {
        try {
          console.log(`Creating Jira ticket for vulnerability: ${vulnerability.title}`);
          const resp = await createJiraTicket(vulnerability);
          console.log(resp)
        } catch (error) {
          console.error(`Error while creating Jira ticket for vulnerability ${vulnerability.title}:`, error);
        }
      }

    })();
  } else {
    console.error('Invalid scan-type provided. Please provide either "snyk" or "zap".');
    core.setFailed('Invalid scan-type provided');
  }
} catch (error) {
  core.setFailed(error.message);
}