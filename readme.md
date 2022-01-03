[comment]: # "Auto-generated SOAR connector documentation"
# ThreatX

Publisher: ThreatX
Connector Version: 1\.0\.1
Product Vendor: ThreatX
Product Name: WAF
Product Version Supported (regex): "\.\*"
Minimum Product Version: 4\.2\.7532

This app implements investigative and enforcement actions on the ThreatX NG WAF platform


The ThreatX Phantom App allows automated enforcement actions, including:

-   temporarily blocking/unblocking IPs
-   Add/Remove IPs in denylist
-   Add/Remove IPs in allowlist

In addition, valuable investigative actions allow you to pull realtime Entity information,
including:

-   Entity metadata
-   Entity IP addresses
-   Entity risk score

Finally, other Entity actions include:

-   read and create Entity notes


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a WAF asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**customer\_name** |  required  | string | Customer Name provided by the ThreatX SOC
**api\_key** |  required  | password | API Key provided by the ThreatX SOC

### Supported Actions
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration
[block ip](#action-block-ip) - Block an IP
[unblock ip](#action-unblock-ip) - Unblock an IP
[add denylist ip](#action-add-denylist-ip) - Add an IP to the Denylist
[remove denylist ip](#action-remove-denylist-ip) - Remove an IP from the Denylist
[app allowlist ip](#action-add-allowlist-ip) - Add an IP to the Allowlist
[remove allowlist ip](#action-remove-allowlist-ip) - Remove an IP from the Allowlist
[get entities](#action-get-entities) - Get high\-level Entity information
[get entity ips](#action-get-entity-ips) - Get all Entity IP addresses
[get entity risk](#action-get-entity-risk) - Get the latest Entity risk score
[get entity notes](#action-get-entity-notes) - Get the Entity notes
[new entity note](#action-new-entity-note) - Add a new note for the Entity

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**
Read only: **True**

This action will attempt to pull the user list from the ThreatX platform to test connectivity\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output

## action: 'block ip'
Block an IP

Type: **contain**
Read only: **False**

Perform a temporary block on an IP

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to block | string |  `ip`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`
action\_result\.status | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.data\.\*\.Ok | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'unblock ip'
Unblock an IP

Type: **correct**
Read only: **False**

Unblock an IP that has been temporarily blocked

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to unblock | string |  `ip`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`
action\_result\.status | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.data\.\*\.Ok | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'denylist ip'
Add an IP to the Denylist

Type: **contain**
Read only: **False**

This action adds an IP to the Denylist as a permanent block\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to add to the Denylist | string |  `ip`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`
action\_result\.status | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.data\.\*\.Ok | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'denylist ip'
Remove an IP from the Denylist

Type: **correct**
Read only: **False**

This action removes an IP from the Denylist so it will no longer be blocked\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to remove from the Denylist | string |  `ip`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`
action\_result\.status | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.data\.\*\.Ok | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'allowlist ip'
Add an IP to the Allowlist

Type: **correct**
Read only: **False**

This action adds an IP to the Allowlist so it will never be blocked\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to add to the Allowlist | string |  `ip`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`
action\_result\.status | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.data\.\*\.Ok | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'allowlist ip'
Remove an IP from the Allowlist

Type: **correct**
Read only: **False**

This action removes an IP from the Allowlist so it can become blocked\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to remove from the Allowlist | string |  `ip`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`
action\_result\.status | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.data\.\*\.Ok | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'get entities'
Get high\-level Entity information

Type: **investigate**
Read only: **True**

This action queries the ThreatX platform for Entities seen by Entity Name, Entity ID, or Entity IP\. The query result provides detailed metadata about the Entity and its lower\-level Actors\. It is often helpful to use this action to query by Entity IP or Entity Name to get the Entity ID, which can be used in other Entity queries\. \(e\.g\. Entity Risk and Entity Notes\)

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity\_name** |  optional  | Name of the Entity | string |  `threatx entity name`
**entity\_id** |  optional  | ID hash of the Entity | string |  `threatx entity id`
**entity\_ip** |  optional  | IP address of the Entity | string |  `ip`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.entity\_name | string |  `threatx entity name`
action\_result\.data\.\*\.id | string |  `threatx entity id`
action\_result\.data\.\*\.actors\.0\.ip\_address | string |  `ip`
action\_result\.data\.\*\.actors\.0\.geo\_country | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.status | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |
action\_result\.data\.\*\.actors\.\*\.hash | numeric |
action\_result\.data\.\*\.actors\.\*\.interval\_time\_stop | numeric |
action\_result\.data\.\*\.actors\.\*\.is\_embargoed | boolean |
action\_result\.data\.\*\.actors\.\*\.state | string |
action\_result\.data\.\*\.actors\.\*\.reputation | numeric |
action\_result\.data\.\*\.actors\.\*\.geo\_coordinates\.y | numeric |
action\_result\.data\.\*\.actors\.\*\.geo\_coordinates\.x | numeric |
action\_result\.data\.\*\.actors\.\*\.state\_update | string |
action\_result\.data\.\*\.actors\.\*\.is\_tor\_exit | boolean |
action\_result\.data\.\*\.actors\.\*\.fingerprint\.count | numeric |
action\_result\.data\.\*\.actors\.\*\.fingerprint\.js\_fingerprint | string |
action\_result\.data\.\*\.actors\.\*\.fingerprint\.cookie | string |
action\_result\.data\.\*\.actors\.\*\.fingerprint\.user\_agent | string |
action\_result\.data\.\*\.actors\.\*\.fingerprint\.last\_seen | numeric |
action\_result\.data\.\*\.actors\.\*\.seq\_blocks | string |
action\_result\.data\.\*\.actors\.\*\.interval\_time\_start | numeric |
action\_result\.data\.\*\.actors\.\*\.entity\_hash | string |
action\_result\.parameter\.entity\_name | string |  `threatx entity name`
action\_result\.parameter\.entity\_ip | string |  `ip`
action\_result\.parameter\.entity\_id | string |  `threatx entity id`

## action: 'get entity ips'
Get all Entity IP addresses

Type: **investigate**
Read only: **True**

This action queries the ThreatX platform for Entities seen by Entity Name, Entity ID, or Entity IP\. The query result provides a list of all IP addresses associated with all of the Entities returned\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity\_name** |  optional  | Name of the Entity | string |  `threatx entity name`
**entity\_id** |  optional  | ID hash of the Entity | string |  `threatx entity id`
**entity\_ip** |  optional  | IP address of the Entity | string |  `ip`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.entity\_name | string |  `threatx entity name`
action\_result\.data\.\*\.entity\_id | string |  `threatx entity id`
action\_result\.data\.\*\.ip | string |  `ip`
action\_result\.data\.\*\.geo\_country | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.status | string |
action\_result\.parameter\.entity\_name | string |  `threatx entity name`
action\_result\.parameter\.entity\_ip | string |  `ip`
action\_result\.parameter\.entity\_id | string |  `threatx entity id`
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'get entity risk'
Get the latest Entity risk score

Type: **investigate**
Read only: **True**

This action queries the ThreatX platform for Entities seen by Entity ID\. The query result provides the current risk score for the Entity\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity\_id** |  required  | ID hash of the Entity | string |  `threatx entity id`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.entity\_id | string |  `threatx entity id`
action\_result\.data\.\*\.risk | numeric |
action\_result\.data\.\*\.pretty\_time | string |
action\_result\.data\.\*\.timestamp | numeric |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.status | string |
action\_result\.parameter\.entity\_id | string |  `threatx entity id`
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'get entity notes'
Get the Entity notes

Type: **investigate**
Read only: **True**

This action queries the ThreatX platform for Entities seen by Entity ID\. The query result provides all notes associated with the Entity\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity\_id** |  required  | ID hash of the Entity | string |  `threatx entity id`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.content | string |
action\_result\.data\.\*\.username | string |  `email`
action\_result\.data\.\*\.pretty\_time | string |
action\_result\.data\.\*\.timestamp | numeric |
action\_result\.data\.\*\.entity\_id | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
action\_result\.status | string |
action\_result\.parameter\.entity\_id | string |  `threatx entity id`
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'new entity note'
Add a new note for the Entity

Type: **generic**
Read only: **False**

This action adds a new note to an Entity\. The Entity is specified by the Entity ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity\_id** |  required  | ID hash of the Entity | string |  `threatx entity id`
**content** |  required  | Content of the note | string |

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.entity\_id | string |  `threatx entity id`
action\_result\.parameter\.content | string |
action\_result\.status | string |
action\_result\.message | string |
action\_result\.summary\.result | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |
action\_result\.data\.\*\.Ok | string |
