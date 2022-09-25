# Task
1. Write the code that will map the detected software (output of task 1) to the CPE entries.<br/>
Python object: `<Software name, CPE name, CPE version>`
2. Write  the code that will output vulnerabilities (CVEs) for the CPE entries. <br/>
Parse [CVE data feed](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) and search vulnerabilities for the detected CPEs.<br/>
[JSON Schema for NVD Vulnerability Data Feed version 1.1](https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema)