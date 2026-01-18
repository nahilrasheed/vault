Continuous Integration, Continuous Delivery, and Continuous Deployment (CI/CD) pipelines are essential for modern software development. They help teams deliver software faster and more efficiently.

**Continuous Integration (CI)** is all about frequently merging code changes from different developers into a central location. This triggers automated processes like building the software and running tests. CI catches problems through an automated process: every time code is integrated, the system automatically builds and tests it. This immediate feedback loop reveals integration problems as soon as they occur. CI helps catch integration problems early, leading to higher quality code. Think of it as the foundation of the pipeline.

**Continuous Delivery** means your code is always ready to be released to users. After passing automated tests, code is automatically deployed to a staging environment (a practice environment) or prepared for final release. Typically, a manual approval step is still needed before going live to production, which provides a control point.

**Continuous Deployment** automates the entire release process. Changes that pass all automated checks are automatically deployed directly to the live production environment, with no manual approval. This is all about speed and efficiency.

![[CI-CD-1765043325442.png]]

## Security Benefits of Continuous Delivery and Deployment
CD allows you to build security checks right into your deployment pipeline.
These automated security checks can include:
- Dynamic Application Security Testing (DAST): Automated tests that find vulnerabilities in running applications in realistic staging environments.
- Security Compliance Checks: Automated checks that ensure software meets your organization’s security rules and policies.
- Infrastructure Security Validations: Checks that make sure the systems hosting your software are secure.
## Importance of secure CI/CD pipelines
- **Secure Automation:** CI/CD automates repetitive tasks: building, testing, deploying. When automation is implemented securely, this reduces errors from manual work, speeds processes, and importantly, reduces human errors that create vulnerabilities. However, insecure automation automates the introduction of vulnerabilities at scale.
- **Improved Code Quality Via Security Checks:** Automated tests in CI/CD rigorously check code before release. Crucially, this includes automated security tests. This leads to fewer bugs and security weaknesses in final software, but only if security tests integrate effectively within the pipeline.
- **Faster Time to Market for Security Updates:** CI/CD accelerates releases. This enables faster delivery of new features, bug fixes, _and security updates_, improving response time to both user needs and security threats. This rapid deployment of security updates is a significant security advantage of a well-secured CI/CD pipeline.
- **Enhanced Collaboration and Feedback with Safety Focus:** CI/CD encourages collaboration between development, security, testing, and operations teams. Quick feedback loops aid identification and resolution of vulnerabilities early in development. This collaborative environment is essential to build security into the pipeline and address vulnerabilities proactively.
- **Reduced Risk:** Frequent, smaller releases, a result of CI/CD, are less risky than large, infrequent releases. If issues arise (including security issues), pinpointing and fixing the problem becomes easier. This also applies to security vulnerabilities; smaller, frequent releases limit the potential impact of a security flaw introduced in any single release, provided security monitoring and testing remain continuous.

## Common CI/CD vulns
### Insecure Dependencies: Risks from Third-Party Code
CI/CD pipelines often use many third-party libraries and components. If these components have known vulnerabilities (Common Vulnerabilities and Exposures, or CVEs), those vulnerabilities can be unknowingly added to your application during the automated build process.

Action Step: Regularly scan and update your dependencies. Make sure you’re using secure versions of all external components.
### Misconfigured Permissions: Controlling Access
Weak access controls in CI/CD tools, code repositories, and related systems are a significant vulnerability. Unauthorized access can allow attackers to modify code, pipeline configurations, or inject malicious content.

Action Step: Implement strong access management using Role-Based Access Control (RBAC). Ensure only authorized individuals can access and change critical pipeline elements.
### Lack of Automated Security Testing: Missing Critical Checks
Failing to include automated security testing in your CI/CD pipeline is a serious error. Without tools like SAST and DAST, you are almost guaranteed to release software full of vulnerabilities that will go undetected until after it's live, leading to significantly higher costs and effort to fix..

Action Step: Integrate automated security testing (SAST and DAST) into your CI/CD pipeline. This should be a core part of your secure CI/CD strategy.
### Exposed Secrets: Protecting Sensitive Information
Hardcoding sensitive data like API keys, passwords, and tokens directly into code or pipeline settings is a serious security mistake. If exposed, these secrets can lead to major security breaches.

Action Step: Never hardcode secrets. Use secure vaults or dedicated secrets management tools to store and manage sensitive information. Enforce this practice across your team.
### Unsecured Build Environments: Protecting the Pipeline Infrastructure
The CI/CD environment itself (the servers and systems that run your pipeline) needs to be secure. If this environment is vulnerable, attackers can compromise it to alter builds, inject malicious code, or steal sensitive data.

Action Step: Harden your build environments. Use secure containers or virtual machines to minimize the risk of a compromised pipeline.

## Building a Secure CI/CD Pipeline: Defense in Depth
To proactively address these vulnerabilities, a layered security approach is key. Here are essential best practices for your CI/CD security strategy:
- **Integrate Security from the Start: Embrace DevSecOps:** Adopt a **DevSecOps** mindset. This means building security into _every_ stage of development, from planning to deployment and beyond. This naturally includes embedding security checks into your CI/CD pipeline.
- **Implement Strong Access Controls:** Use strict permission policies based on the principle of least privilege. Only grant necessary access to code, pipeline settings, and deployment configurations. Use tools like Multi-Factor Authentication (MFA) and Role-Based Access Control (RBAC) to secure your CI/CD environment.
- **Automate Security Testing Everywhere:** Make automated security scans and tests a fundamental part of your build and deployment process. Tools like SAST, Software Composition Analysis (SCA), and DAST are not optional extras – they are essential for a secure CI/CD pipeline so you can catch vulnerabilities early.
- **Keep Dependencies Updated:** Maintain a current inventory of all third-party dependencies, libraries, and CI/CD plugins. Regularly update these components to patch security vulnerabilities (CVEs). Tools like [Dependabot](https://docs.github.com/en/code-security/getting-started/dependabot-quickstart-guide) and [Snyk](https://snyk.io/) can automate dependency management.
- **Secure Secrets Management:** Never hardcode sensitive information in your code or pipeline configurations. Require the use of dedicated secrets management tools like HashiCorp Vault or AWS Secrets Manager. Securely store, access, and rotate secrets throughout the CI/CD process.

## Common Indicators of Compromise (IoCs) in CI/CD Pipelines
Understanding common CI/CD IoCs helps you monitor effectively and quickly find security incidents. Here are some examples:
- **Unauthorized Code Changes:**
    - Code changes from people who shouldn't be making changes.
    - Code changes made at unusual times or from unexpected locations.
    - Code changes that look suspicious, like confusing code, very large deletions without a good reason, or code that doesn't follow coding rules.
- **Suspicious Deployment Patterns:**
    - Deployments to unusual or unapproved systems (for example, production deployments started directly from developer branches).
    - Deployments happening at unexpected times or too often (deployments outside of planned release times).
    - Deployments started by unusual user accounts or automated accounts that shouldn't be releasing to production.
- **Compromised Dependencies:**
    - Finding known vulnerabilities (CVEs) in dependencies during automated checks in the CI/CD pipeline.
    - Suddenly adding new, unexpected dependencies to build settings.
    - Attempts to download dependencies from unofficial or untrusted sources.
- **Unusual Pipeline Execution:**
    - Pipeline steps that normally work fine suddenly failing.
    - Pipelines takeing much longer to run for no clear reason.
    - Changes in the order or way pipeline steps run without approved changes being made.
- **Secrets Exposure Attempts:**
    - Logs showing attempts to get to secrets from unapproved places in the pipeline.
    - Finding private secrets hardcoded in code changes (ideally prevented earlier, but monitoring can catch mistakes).

## Using Automation to Find Anomalies and IoCs
To monitor CI/CD pipelines and automatically find threats, you can use these methods:
### Comprehensive Logging and Auditing 
Detailed logs are the bases of monitoring. Logs provide the raw data that monitoring tools check for unusual activity and potential Indicators of Compromise (IoCs). The most common logs for finding anomalies include:
- **Pipeline Execution Logs:** To effectively leverage pipeline execution logs for security monitoring, specialized tools employ automated baselining techniques. These tools analyze logs from successful, typical CI/CD pipeline runs to establish a profile of normal operation. This baseline encompasses key performance indicators such as the standard duration of each pipeline stage and expected success and failure rates. By continuously monitoring execution logs and comparing them against this established baseline, the tools can automatically detect anomalous activities. Deviations from the norm, including pipeline steps exceeding typical execution times, unexpected error occurrences, or alterations in the usual step order, are flagged as potential Indicators of Compromise (IoCs), warranting further security scrutiny.
- **Code Commit Logs:** Keep track of code changes for each pipeline run. Unusual code changes, such as changes from people who shouldn't be making changes, changes made late at night, or changes with suspicious content (like very large deletions or confusing code), are important IoCs to monitor.
- **Access Logs:** Monitoring tools can learn who usually accesses CI/CD. Unusual logins, like logins from different countries, failed login attempts followed by a successful login, or login attempts to change important pipeline settings, are strong indicators of compromise.
- **Deployment Logs:** Tools can learn how often deployments usually happen and what those deployments look like. Unusual deployments, such as deployments at odd times or deployments to unexpected places, can be IoCs.
### Security Information and Event Management (SIEM) Integration
Connecting your CI/CD logs to a SIEM tool can help  automatically find anomalies at a large scale. SIEM platforms are made to:
- **Automatically Find Anomalies:** SIEMs use machine learning and analytics to automatically find unusual patterns in CI/CD logs, which are  possible IoCs to investigate.
- **Use Rules to Alert for Known IoCs:** You can set up specific rules in the SIEM to find known CI/CD IoCs. For example, rules can send alerts when:
    - Detection of specific malicious file hashes (related to known CI/CD attacks) are found in build results.
    - CI/CD servers connect to known malicious command and control (C2) servers (using threat intelligence data).
    - Someone tries to download or access private secrets outside of approved pipeline steps.
### Real-time Alerting and Notifications 
Automated alerts make sure security teams are notified right away about unusual activity and possible IoCs, so they can respond quickly. Alerts should be set up for:
- **Unusual Build Failures:** Pipeline steps failing repeatedly, especially after code changes that shouldn't cause failures.
- **Suspicious Code Changes (Based on Anomalies):** Alerts sent by code analysis tools that find highly unusual code changes based on size, author, or confusing content.
- **Attempts to Expose Secrets:** Alerts sent by security tools when someone tries to access or steal secrets from unapproved parts of the pipeline.
- **Unusual Network Traffic:** Alerts for unusual network traffic from CI/CD servers, especially traffic going out to unknown or suspicious locations.
### Performance Monitoring to Find IoAs and Discover IoCs 
Performance monitoring, while mainly used to make sure things are running smoothly, can also indirectly help find IoCs. Performance issues (Indicators of Attack - IoAs) like sudden slowdowns or CI/CD servers running out of resources can lead to deeper checks that may uncover IoCs.
### Continuous Vulnerability Scanning
Regularly checking the CI/CD infrastructure for weaknesses can proactively find vulnerable parts. This includes Common Vulnerabilities and Exposures (CVEs) in CI/CD tools, plugins, and containers. These weaknesses are potential IoCs. They highlight areas that need to be patched right away to prevent attacks and possible pipeline compromise.


---
## Resources:
1. DevSecOps Using GitHub Actions: Building Secure CI/CD Pipelines. [https://medium.com/@rahulsharan512/devsecops-using-github-actions-building-secure-ci-cd-pipelines-5b6d59acab32](https://medium.com/@rahulsharan512/devsecops-using-github-actions-building-secure-ci-cd-pipelines-5b6d59acab32)
2. 6 Steps for Success with CI/CD Securing Hardening. [https://spectralops.io/blog/ci-cd-security-hardening/](https://spectralops.io/blog/ci-cd-security-hardening/)
3. GitLab CI/CD - Hands-On Lab: Securing Scanning. [https://handbook.gitlab.com/handbook/customer-success/professional-services-engineering/education-services/gitlabcicdhandsonlab9/](https://handbook.gitlab.com/handbook/customer-success/professional-services-engineering/education-services/gitlabcicdhandsonlab9/)
4. How can you stay current with the latest problem solving techniques in Cloud Computing as a manager. [https://www.linkedin.com/advice/1/how-can-you-stay-current-latest-problem-solving-msk5e](https://www.linkedin.com/advice/1/how-can-you-stay-current-latest-problem-solving-msk5e)
5. 1. What is CI/CD? - Continuous Integration, Delivery, and Deployment. [https://www.threatintelligence.com/blog/continuous-integration-continuous-delivery](https://www.threatintelligence.com/blog/continuous-integration-continuous-delivery)
6. 1. Optimizing logs for a more effective CI/CD pipeline [Best Practices]. [https://coralogix.com/blog/optimizing-logs-for-a-more-effective-ci-cd-pipeline/](https://coralogix.com/blog/optimizing-logs-for-a-more-effective-ci-cd-pipeline/)
7. Streamline Your CI/CD: Hand-on Anomaly Detection with AI. [https://www.latesttechinsights.com/2024/04/streamline-your-cicd-hands-on-anomaly.html](https://www.latesttechinsights.com/2024/04/streamline-your-cicd-hands-on-anomaly.html)
8. CI/CD & DevOps Pipelines: An Introduction. [https://www.splunk.com/en_us/blog/learn/ci-cd-devops-pipeline.html](https://www.splunk.com/en_us/blog/learn/ci-cd-devops-pipeline.html)