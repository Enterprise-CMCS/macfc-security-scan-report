const fs = require('fs');
const axios = require('axios').default; 
const core = require('@actions/core');
const path = require('path');

// Install dependencies 
const installDependency = (dependency) => {
  core.startGroup(`Installing ${dependency}`);
  const installResult = require('child_process').spawnSync('npm', ['install', dependency], { stdio: 'inherit' });
  core.endGroup();
  return installResult;
};

const installDependencies = (dependencies) => {
  dependencies.forEach(dependency => installDependency(dependency));
};

const token = core.getInput('jira-token');
const jira = axios.create({
    baseURL: `https://${core.getInput('jira-host')}`,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

const jiraheaders = {  
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
};

// Function to check if the user exists using the Jira REST API
async function doesUserExist(username) {
  try {
    const username = core.getInput('jira-username');
    const token = core.getInput('jira-token'); 
    const response = await fetch(`https://${core.getInput('jira-host')}/rest/api/3/user?username=${username}`, {
      method: 'GET',
      headers: {
        'Authorization': `Basic ${Buffer.from(
          `${username}:${token}`
        ).toString('base64')}`,
        'Accept': 'application/json'
      }
    });

    if (response.status === 200) {
      // User exists (status code 200 OK)
      console.log(response.status);
      return true;
    } else if (response.status === 404) {
      // User does not exist (status code 404 Not Found)
      console.log(response.status);
      return false;
    } else {
      // Handle other response statuses if needed
      throw new Error(`Unexpected response status: ${response.status} ${response.statusText}`);
    }
  } catch (err) {
    console.error(err);
    return false; // Return false if there was an error during the HTTP request
  }
}

try {
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
      let searchResponse = await jira.get('/rest/api/2/search', { params: { jql: jqlQuery } });
      let searchResult = searchResponse.data;

      if (!searchResult.issues || searchResult.issues.length === 0) {
        const customFieldKeyValue = core.getInput('jira-custom-field-key-value') ? JSON.parse(core.getInput('jira-custom-field-key-value')) : null;
        const customJiraFields = customFieldKeyValue ? { ...customFieldKeyValue } : null;

        const username = core.getInput('assign-jira-ticket-to');
        const assignee = await doesUserExist(username).catch(() => null)

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
            assignee: {
              name: assignee ? username : null,
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
          if (Array.isArray(data)) {
            for (const project of data) {
              if (project && project.vulnerabilities && Array.isArray(project.vulnerabilities)) {
                vulnerabilities = vulnerabilities.concat(project.vulnerabilities);
              }
            }
          } else {
            console.error('No Vulnerabilities Detetcted or Invalid JSON data format.');
            // vulnerabilities = parseNonJsonData(inputData);
          }
        } catch (error) {
          console.error('Error parsing Snyk output:', error);
          // vulnerabilities = parseNonJsonData(inputData);
        }
      }
      return vulnerabilities;
    }


    // function parseNonJsonData(inputData) {
    //   let vulnerabilities = [];

    //   // Custom logic to parse non-JSON inputData
    //   const defaultTitle = 'Vulnerability Detected';

    //   vulnerabilities.push({
    //     title: defaultTitle,
    //     description: `Non-JSON output from Snyk:\n\n${inputData}`
    //   });

    //   return vulnerabilities;
    // }


    async function createJiraTicket(vulnerability) {
      // JQL query with relative date math, status conditions.
      const title = vulnerability.title.replaceAll("\"", "\\\"");
      let jqlQuery = `project = "${core.getInput('jira-project-key')}" AND summary ~ "${vulnerability.title}" AND created >= startOfDay("-60d") AND status NOT IN ("Closed", "Cancelled")`;
      let searchResponse = await jira.get('/rest/api/2/search', { params: { jql: jqlQuery } });
      let searchResult = searchResponse.data;

      if (!searchResult.issues || searchResult.issues.length === 0) {
        const customFieldKeyValue = core.getInput('jira-custom-field-key-value') ? JSON.parse(core.getInput('jira-custom-field-key-value')) : null;
        const customJiraFields = customFieldKeyValue ? { ...customFieldKeyValue } : null;

        const username = core.getInput('assign-jira-ticket-to');
        const assignee = await doesUserExist(username).catch(() => null)

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
            assignee: {
              name: assignee ? username : null,
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

      const uniqueVulnerabilities = Array.from(new Set(vulnerabilities.map(v => v.title)))
        .map(title => {
          return vulnerabilities.find(v => v.title === title);
        });

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