[comment]: # "Auto-generated SOAR connector documentation"
# Carbon Black Protection Bit9

Publisher: Splunk  
Connector Version: 2\.1\.3  
Product Vendor: Carbon Black  
Product Name: Carbon Black Protection  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app supports various investigative and containment actions on Carbon Black Enterprise Protection \(formerly Bit9\)

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Carbon Black Protection asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Device URL, e\.g\. https\://mycb\.enterprise\.com
**api\_token** |  required  | password | API Token
**verify\_server\_cert** |  required  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the API Token by attempting to connect to the Device URL\. This action runs a quick query on the device to check the connection and token  
[hunt file](#action-hunt-file) - Searches for a particular file across all the endpoints  
[upload file](#action-upload-file) - Upload a file to a computer  
[analyze file](#action-analyze-file) - Analyze a file on a computer  
[unblock hash](#action-unblock-hash) - Unblocks a particular hash  
[block hash](#action-block-hash) - Ban the file hash  
[get system info](#action-get-system-info) - Get information about an endpoint  

## action: 'test connectivity'
Validate the API Token by attempting to connect to the Device URL\. This action runs a quick query on the device to check the connection and token

Type: **test**  
Read only: **True**

This action requires the following permission\: <ul><li>View files</li></ul>\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'hunt file'
Searches for a particular file across all the endpoints

Type: **investigate**  
Read only: **True**

This action requires the following permission\: <ul><li>View files</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash value of the file | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data\.\*\.approvedByReputation | boolean | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.certificateId | numeric | 
action\_result\.data\.\*\.certificateState | numeric | 
action\_result\.data\.\*\.company | string | 
action\_result\.data\.\*\.computerId | string |  `carbon black computer id` 
action\_result\.data\.\*\.dateCreated | string | 
action\_result\.data\.\*\.effectiveState | string | 
action\_result\.data\.\*\.fileExtension | string | 
action\_result\.data\.\*\.fileFlags | numeric | 
action\_result\.data\.\*\.fileName | string | 
action\_result\.data\.\*\.fileSize | numeric | 
action\_result\.data\.\*\.fileState | numeric | 
action\_result\.data\.\*\.fileType | string | 
action\_result\.data\.\*\.id | numeric |  `carbon black file id` 
action\_result\.data\.\*\.installedProgramName | string | 
action\_result\.data\.\*\.md5 | string | 
action\_result\.data\.\*\.pathName | string | 
action\_result\.data\.\*\.prevalence | numeric | 
action\_result\.data\.\*\.productName | string | 
action\_result\.data\.\*\.productVersion | string | 
action\_result\.data\.\*\.publisher | string | 
action\_result\.data\.\*\.publisherId | numeric | 
action\_result\.data\.\*\.publisherOrCompany | string | 
action\_result\.data\.\*\.publisherState | numeric | 
action\_result\.data\.\*\.reputationAvailable | boolean | 
action\_result\.data\.\*\.reputationEnabled | boolean | 
action\_result\.data\.\*\.sha1 | string | 
action\_result\.data\.\*\.sha256 | string | 
action\_result\.data\.\*\.sha256HashType | numeric | 
action\_result\.data\.\*\.threat | numeric | 
action\_result\.data\.\*\.trust | numeric | 
action\_result\.data\.\*\.trustMessages | string | 
action\_result\.summary\.prevalence | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'upload file'
Upload a file to a computer

Type: **generic**  
Read only: **False**

This action requires the following permissions\: <ul><li>View file uploads</li><li>Manage uploads of inventoried files</li></ul>It has been noticed that the default <b>admin</b> account does <i>not</i> have the required permissions to execute this action\. Please create a new user with the required permissions for this app\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_id** |  required  | File ID | numeric |  `carbon black file id` 
**computer\_id** |  required  | Computer ID | numeric |  `carbon black computer id` 
**priority** |  optional  | Priority | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.computer\_id | numeric |  `carbon black computer id` 
action\_result\.parameter\.file\_id | numeric |  `carbon black file id` 
action\_result\.parameter\.priority | numeric | 
action\_result\.data\.\*\.computerId | numeric | 
action\_result\.data\.\*\.uploadPath | string | 
action\_result\.data\.\*\.dateModified | string | 
action\_result\.data\.\*\.uploadedFileSize | numeric | 
action\_result\.data\.\*\.createdBy | string | 
action\_result\.data\.\*\.createdByUserId | numeric | 
action\_result\.data\.\*\.dateCreated | string | 
action\_result\.data\.\*\.fileCatalogId | numeric | 
action\_result\.data\.\*\.fileName | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.pathName | string |  `file path` 
action\_result\.data\.\*\.priority | numeric | 
action\_result\.data\.\*\.uploadStatus | numeric | 
action\_result\.summary\.upload\_status | numeric | 
action\_result\.summary\.upload\_status\_desc | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'analyze file'
Analyze a file on a computer

Type: **investigate**  
Read only: **False**

This action requires the following permissions\: <ul><li>View files</li><li>Submit files for analysis</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_id** |  required  | File ID | numeric |  `carbon black file id` 
**computer\_id** |  required  | Computer ID | numeric |  `carbon black computer id` 
**connector\_id** |  required  | Connector ID | numeric |  `carbon black connector id` 
**target\_type** |  required  | Analysis Target | string |  `carbon black analysis target` 
**priority** |  optional  | Priority | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.computer\_id | numeric |  `carbon black computer id` 
action\_result\.parameter\.connector\_id | numeric |  `carbon black connector id` 
action\_result\.parameter\.file\_id | numeric |  `carbon black file id` 
action\_result\.parameter\.priority | numeric | 
action\_result\.parameter\.target\_type | string |  `carbon black analysis target` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.fileName | string | 
action\_result\.data\.\*\.pathName | string | 
action\_result\.data\.\*\.priority | numeric | 
action\_result\.data\.\*\.createdBy | string | 
action\_result\.data\.\*\.computerId | numeric | 
action\_result\.data\.\*\.connectorId | numeric | 
action\_result\.data\.\*\.dateCreated | string | 
action\_result\.data\.\*\.dateModified | string | 
action\_result\.data\.\*\.fileCatalogId | numeric | 
action\_result\.data\.\*\.analysisResult | numeric | 
action\_result\.data\.\*\.analysisStatus | numeric | 
action\_result\.data\.\*\.analysisTarget | string | 
action\_result\.data\.\*\.createdByUserId | numeric | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.computerId | numeric | 
action\_result\.data\.\*\.connectorId | numeric | 
action\_result\.data\.\*\.analysisStatus | numeric | 
action\_result\.data\.\*\.fileName | string | 
action\_result\.data\.\*\.priority | numeric | 
action\_result\.data\.\*\.createdByUserId | numeric | 
action\_result\.data\.\*\.pathName | string |  `file path` 
action\_result\.data\.\*\.fileCatalogId | numeric | 
action\_result\.data\.\*\.createdBy | string | 
action\_result\.data\.\*\.analysisResult | numeric | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.dateCreated | string | 
action\_result\.data\.\*\.dateModified | string | 
action\_result\.data\.\*\.analysisTarget | string | 
action\_result\.message | string | 
action\_result\.summary\.analysis\_status | numeric | 
action\_result\.summary\.analysis\_status\_desc | string |   

## action: 'unblock hash'
Unblocks a particular hash

Type: **correct**  
Read only: **False**

This action requires the following permissions\: <ul><li>View files</li><li>Manage files</li></ul>Sets the global state of the hash to either <b>approved</b> or <b>unapproved</b> by updating the file rule\. If the action does not find a rule for the hash, it will return an error\. If the hash rule found by the action does not contain a description containing a matching Phantom Identification ID, it will return an error status without changing the state of the rule\. This is to make sure the app only modifies rules that have been created or updated by itself\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File Hash to unblock | string |  `hash`  `sha256`  `sha1`  `md5` 
**file\_state** |  optional  | File state to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_state | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data\.\*\.clVersion | numeric | 
action\_result\.data\.\*\.createdBy | string | 
action\_result\.data\.\*\.createdByUserId | numeric | 
action\_result\.data\.\*\.dateCreated | string | 
action\_result\.data\.\*\.dateModified | string | 
action\_result\.data\.\*\.platformFlags | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.fileCatalogId | numeric | 
action\_result\.data\.\*\.fileState | numeric | 
action\_result\.data\.\*\.forceInstaller | boolean | 
action\_result\.data\.\*\.forceNotInstaller | boolean | 
action\_result\.data\.\*\.hash | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.modifiedBy | string | 
action\_result\.data\.\*\.modifiedByUserId | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.policyIds | string | 
action\_result\.data\.\*\.reportOnly | boolean | 
action\_result\.data\.\*\.reputationApprovalsEnabled | boolean | 
action\_result\.data\.\*\.sourceId | numeric | 
action\_result\.data\.\*\.sourceType | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block hash'
Ban the file hash

Type: **contain**  
Read only: **False**

This action requires the following permissions\: <ul><li>View files</li><li>Manage files</li></ul>Sets the global state of the file hash to <b>ban</b> by adding or updating a <i>file rule</i>\. If a file is found in the catalog, the action will use the catalog id in the rule\. The action also appends the Phantom Installation ID to the description of the rule\. This is the action's way of tagging rules that are created by the app\. If the action finds the current state of the file as <i>banned</i> it does not attempt to set the state, this also results in the description of the rule remaining unchanged\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File Hash to block/ban | string |  `hash`  `sha256`  `sha1`  `md5` 
**comment** |  optional  | Description to add to the block rule | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data\.\*\.platformFlags | numeric | 
action\_result\.data\.\*\.clVersion | numeric | 
action\_result\.data\.\*\.createdBy | string | 
action\_result\.data\.\*\.createdByUserId | numeric | 
action\_result\.data\.\*\.dateCreated | string | 
action\_result\.data\.\*\.dateModified | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.fileCatalogId | numeric | 
action\_result\.data\.\*\.fileState | numeric | 
action\_result\.data\.\*\.forceInstaller | boolean | 
action\_result\.data\.\*\.forceNotInstaller | boolean | 
action\_result\.data\.\*\.hash | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.modifiedBy | string | 
action\_result\.data\.\*\.modifiedByUserId | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.policyFlags | string | 
action\_result\.data\.\*\.policyIds | string | 
action\_result\.data\.\*\.policyIds | string | 
action\_result\.data\.\*\.reportOnly | boolean | 
action\_result\.data\.\*\.reputationApprovalsEnabled | boolean | 
action\_result\.data\.\*\.sourceId | numeric | 
action\_result\.data\.\*\.sourceType | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system info'
Get information about an endpoint

Type: **investigate**  
Read only: **True**

This action requires the following permission\: <ul><li>View computers</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | Hostname/IP address to get info of | string |  `ip`  `host name` 
**id** |  optional  | Computer id | numeric |  `carbon black computer id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | numeric |  `carbon black computer id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.CLIPassword | string | 
action\_result\.data\.\*\.SCEPStatus | numeric | 
action\_result\.data\.\*\.activeDebugFlags | numeric | 
action\_result\.data\.\*\.activeDebugLevel | numeric | 
action\_result\.data\.\*\.activeKernelDebugLevel | numeric | 
action\_result\.data\.\*\.agentCacheSize | numeric | 
action\_result\.data\.\*\.agentMemoryDumps | numeric | 
action\_result\.data\.\*\.agentQueueSize | numeric | 
action\_result\.data\.\*\.computerTag | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.templateDate | string | 
action\_result\.data\.\*\.upgradeError | string | 
action\_result\.data\.\*\.cbSensorVersion | string | 
action\_result\.data\.\*\.upgradeErrorTime | string | 
action\_result\.data\.\*\.templateCloneCleanupMode | string | 
action\_result\.data\.\*\.templateCloneCleanupTime | string | 
action\_result\.data\.\*\.templateCloneCleanupTimeScale | string | 
action\_result\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.automaticPolicy | boolean | 
action\_result\.data\.\*\.cbSensorFlags | numeric | 
action\_result\.data\.\*\.cbSensorId | numeric | 
action\_result\.data\.\*\.ccFlags | numeric | 
action\_result\.data\.\*\.ccLevel | numeric | 
action\_result\.data\.\*\.clVersion | numeric | 
action\_result\.data\.\*\.connected | boolean | 
action\_result\.data\.\*\.dateCreated | string | 
action\_result\.data\.\*\.daysOffline | numeric | 
action\_result\.data\.\*\.debugDuration | numeric | 
action\_result\.data\.\*\.debugFlags | numeric | 
action\_result\.data\.\*\.debugLevel | numeric | 
action\_result\.data\.\*\.deleted | boolean | 
action\_result\.data\.\*\.disconnectedEnforcementLevel | numeric | 
action\_result\.data\.\*\.enforcementLevel | numeric | 
action\_result\.data\.\*\.forceUpgrade | boolean | 
action\_result\.data\.\*\.hasDuplicates | boolean | 
action\_result\.data\.\*\.hasHealthCheckErrors | boolean | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.initPercent | numeric | 
action\_result\.data\.\*\.initializing | boolean | 
action\_result\.data\.\*\.ipAddress | string |  `ip` 
action\_result\.data\.\*\.isActive | boolean | 
action\_result\.data\.\*\.kernelDebugLevel | numeric | 
action\_result\.data\.\*\.lastPollDate | string | 
action\_result\.data\.\*\.lastRegisterDate | string | 
action\_result\.data\.\*\.localApproval | boolean | 
action\_result\.data\.\*\.macAddress | string | 
action\_result\.data\.\*\.machineModel | string | 
action\_result\.data\.\*\.memorySize | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.osName | string | 
action\_result\.data\.\*\.osShortName | string | 
action\_result\.data\.\*\.platformId | numeric | 
action\_result\.data\.\*\.policyId | numeric | 
action\_result\.data\.\*\.policyName | string | 
action\_result\.data\.\*\.policyStatus | string | 
action\_result\.data\.\*\.policyStatusDetails | string | 
action\_result\.data\.\*\.previousPolicyId | numeric | 
action\_result\.data\.\*\.prioritized | boolean | 
action\_result\.data\.\*\.processorCount | numeric | 
action\_result\.data\.\*\.processorModel | string | 
action\_result\.data\.\*\.processorSpeed | numeric | 
action\_result\.data\.\*\.refreshFlags | numeric | 
action\_result\.data\.\*\.supportedKernel | boolean | 
action\_result\.data\.\*\.syncFlags | numeric | 
action\_result\.data\.\*\.syncPercent | numeric | 
action\_result\.data\.\*\.systemMemoryDumps | numeric | 
action\_result\.data\.\*\.tamperProtectionActive | boolean | 
action\_result\.data\.\*\.tdCount | numeric | 
action\_result\.data\.\*\.template | boolean | 
action\_result\.data\.\*\.templateComputerId | numeric | 
action\_result\.data\.\*\.templateTrackModsOnly | boolean | 
action\_result\.data\.\*\.uninstalled | boolean | 
action\_result\.data\.\*\.upgradeErrorCount | numeric | 
action\_result\.data\.\*\.upgradeStatus | string | 
action\_result\.data\.\*\.users | string | 
action\_result\.data\.\*\.virtualPlatform | string | 
action\_result\.data\.\*\.virtualized | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 