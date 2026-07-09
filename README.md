# Entra ID Audit Logs: Cybersecurity Technical Write-Up 

  

## Purpose 

This write-up explains how Microsoft Entra ID audit logs support post-compromise investigation by revealing what changes were made, who made them, and which identities or objects were affected. It is intended to help an analyst move beyond initial compromise confirmation and determine whether an attacker established persistence, escalated privilege, or altered identity controls inside the tenant. 

  

## Executive overview 

Entra ID audit logs are the main identity data source for reconstructing administrative activity after a compromised account has been identified. While sign-in logs show how access was gained, audit logs show what the attacker did next, such as resetting passwords, adding MFA methods, modifying accounts, assigning roles, or registering applications. For a SOC or IAM analyst, this makes audit logs critical for scoping impact, identifying persistence mechanisms, and deciding which recovery actions are necessary. 

  

## Technical context 

A successful identity attack rarely stops at authentication. Once inside an Entra tenant, an attacker often tries to harden access, expand permissions, and create alternate paths back into the environment. Common post-compromise objectives include maintaining access through password changes or MFA changes, escalating privileges through role assignment, changing user attributes to evade detection, and creating malicious or unauthorized applications for longer-term abuse. 

  

This is why audit telemetry matters. Entra ID functions as the identity and access control layer for users, apps, devices, and policy decisions across Microsoft 365, Azure-connected resources, and external integrations. Changes to roles, groups, authentication settings, and directory objects affect what identities can do and how future sign-ins are evaluated, so audit records often reveal the attacker’s intent more clearly than the original sign-in event. Governance features such as privileged access management, access reviews, and lifecycle controls depend on trustworthy records of administrative actions, which further increases the operational value of audit logs. 

  

## Technical detail 

The lab identifies the base Splunk filter for this telemetry as `index=scenario sourcetype="azure:aad:audit"`. That query surfaces administrative and configuration changes across the Entra environment, including changes made directly by user accounts and those executed by apps or services. In contrast to sign-in data, which focuses on authentication attempts, audit logs focus on state changes to identities, policies, and directory objects. 

  

Three fields are especially important during analysis: `activityDisplayName`, `initiatedBy`, and `targetResources`. `activityDisplayName` describes the action itself, such as changing a user password or disabling an account. `initiatedBy` identifies the actor, which may be a user principal name or an application or service principal display name. `targetResources` identifies what object was changed and can include nested `modifiedProperties` that show the specific settings altered, such as `ForceChangePassword` changing from `False` to `True`. 

  

That combination gives an analyst a practical triage model: what changed, who changed it, and what was affected. For example, if a compromised user account appears in `initiatedBy.user.userPrincipalName`, the event may show direct attacker activity from that identity. If the change was initiated by an app such as the Microsoft password reset service, the analyst must determine whether that app execution reflects expected workflow automation or a user-initiated action routed through a trusted service. 

  

The lab provide two useful investigation patterns. The first query filters all changes targeting a specific compromised user by matching `targetResources{}.userPrincipalName`, then normalizes the actor with `coalesce` so the output captures either a user or app initiator in one field. This is valuable when asking, “What happened to this account after compromise?” The second query filters for all changes performed by a specific user through `initiatedBy.user.userPrincipalName`, which answers the complementary question, “What did this account change elsewhere in the tenant?” 

  

These two pivots are especially effective when paired with sign-in log findings. Sign-in logs can confirm the suspicious authentication sequence, source IP, MFA outcome, and application access path, while audit logs reveal whether the attacker translated that access into persistence or privilege escalation. Together, they form a practical identity incident timeline from initial access through post-authentication actions. 

  

## Indicators and observables 

High-value observables in Entra ID audit investigations include: 

  

- `activityDisplayName` values related to password reset, account disablement, MFA registration changes, role assignments, and application registration. 

- `initiatedBy.user.userPrincipalName` showing a user-driven change from the compromised identity. 

- `initiatedBy.app.displayName` or service principal details indicating an application or automation path. 

- `targetResources{}.userPrincipalName` identifying the affected identity. 

- `modifiedProperties` showing exact before-and-after values, such as password-related flags. 

- Role or privilege changes that could expand the attacker’s access and blast radius. 

- Authentication-method changes that support persistence, especially new MFA registrations or recovery paths. 

  

## Blind spots and limitations 

Audit logs are essential, but they do not capture every downstream action taken after access is obtained. They show directory and administrative changes, not full user activity inside Exchange, Teams, SharePoint, or endpoints, so additional Microsoft 365, endpoint, and application logs may be needed to fully scope impact. They also require analysts to understand the difference between direct user actions and service-mediated actions, since a benign platform service may appear as the executor even when the originating cause was user behavior. 

  

## False positives and benign triggers 

Several legitimate activities can resemble malicious post-compromise actions: 

  

- Help desk or approved self-service password reset workflows changing password-related properties. 

- Routine MFA re-registration after device replacement or enrollment changes. 

- Authorized administrators assigning roles or updating user attributes as part of normal operations. 

- Provisioning or workflow automation modifying accounts during onboarding, department moves, or offboarding. 

- Application registrations created for legitimate integrations, automation, or governance workflows. 

  

## Response actions 

When suspicious audit activity is found, a disciplined response should include: 

  

1. Correlate the audit events with sign-in logs to confirm the access path, timing, and source of compromise. 

2. Review all changes targeting the compromised identity and all actions performed by it across the tenant. 

3. Revoke sessions, reset credentials, and review MFA methods or recovery options for unauthorized additions. 

4. Check for privileged role assignments, group changes, application registrations, and other persistence mechanisms. 

5. Validate each suspicious change with system owners or admins, then revert unauthorized modifications. 

6. Strengthen defenses with MFA, Conditional Access, privileged access governance, and regular access reviews to reduce repeat abuse. 

  

## Analyst takeaway 

Entra ID audit logs are the authoritative record for understanding how a compromise changed the tenant’s identity state after the attacker got in. For an analyst, their value is not just in proving that a change happened, but in reconstructing attacker objectives, identifying persistence, and ensuring the environment is returned to a known-good state rather than merely locking the front door again. 
