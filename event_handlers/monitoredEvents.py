#!/usr/bin/python
# -*- coding: utf-8 -*-

import event_api, event_halo_user, event_halo_portal, event_svm, event_daemon, event_sam, event_fim, \
    event_fw, event_ghostport, event_server, event_lids, event_halo_acct, event_sca

events_classification = {
    "activation_link_failed": {
        "lib": event_halo_user,
        "description": "Halo user activation failed."
    },
    "api_client_created": {
        "lib": event_api,
        "description": "Api key created."
    },
    "api_client_deleted": {
        "lib": event_api,
        "description": "Api key deleted."
    },
    "api_client_secret_viewed": {
        "lib": event_api,
        "description": "Api secret key viewed."
    },
    "api_client_updated": {
        "lib": event_api,
        "description": "Api key modified."
    },
    "api_login_success": {
        "lib": event_api,
        "description": "Halo API authentication success (Client receives access token)."
    },
    "authorized_ips_modified": {
        "lib": event_halo_portal,
        "description": "Authorized ips modified (Authorized IP addresses)."
    },
    "cve_exception_created": {
        "lib": event_svm,
        "description": "Software vulnerability exception created."
    },
    "cve_exception_expired": {
        "lib": event_svm,
        "description": "Software vulnerability exception expired."
    },
    "cve_exception_deleted": {
        "lib": event_svm,
        "description": "Software vulnerability exception deleted."
    },
    "daemon_compromised": {
        "lib": event_daemon,
        "description": "Daemon compromised."
    },
    "daemon_version_change": {
        "lib": event_daemon,
        "description": "Daemon version changed."
    },
    "duplicate_uid_accounts": {
        "lib": event_sam,
        "description": "Multiple accounts detected with same UID."
    },
    "fim_baseline_created": {
        "lib": event_fim,
        "description": "File integrity baseline created."
    },
    "fim_baseline_deleted": {
        "lib": event_fim,
        "description": "File integrity baseline deleted."
    },
    "fim_baseline_expired": {
        "lib": event_fim,
        "description": "File integrity baseline expired."
    },
    "fim_baseline_failed": {
        "lib": event_fim,
        "description": "File integrity baseline failed (Baseline scan failed)."
    },
    "fim_baseline_invalid": {
        "lib": event_fim,
        "description": "File integrity baseline invalid (policy changed/too many objects)."
    },
    "fim_exception_created": {
        "lib": event_fim,
        "description": "File integrity exception created."
    },
    "fim_exception_deleted": {
        "lib": event_fim,
        "description": "File integrity exception deleted."
    },
    "fim_exception_expired": {
        "lib": event_fim,
        "description": "File integrity exception expired."
    },
    "fim_object_added": {
        "lib": event_fim,
        "description": "File integrity object added (DEPRECATED)."
    },
    "fim_object_missing": {
        "lib": event_fim,
        "description": "File integrity object missing (DEPRECATED)."
    },
    "fim_policy_assigned": {
        "lib": event_fim,
        "description": "File integrity policy assigned (Assigned to a server group)."
    },
    "fim_policy_created": {
        "lib": event_fim,
        "description": "File integrity policy created."
    },
    "fim_policy_deleted": {
        "lib": event_fim,
        "description": "File integrity policy deleted."
    },
    "fim_policy_exported": {
        "lib": event_fim,
        "description": "File integrity policy exported."
    },
    "fim_policy_imported": {
        "lib": event_fim,
        "description": "File integrity policy."
    },
    "fim_policy_modified": {
        "lib": event_fim,
        "description": "File integrity policy modified."
    },
    "fim_policy_unassigned": {
        "lib": event_fim,
        "description": "File integrity policy unassigned."
    },
    "fim_re_baseline": {
        "lib": event_fim,
        "description": "File integrity re-baseline."
    },
    "fim_scan_disabled": {
        "lib": event_fim,
        "description": "Automatic file integragion scanning disabled."
    },
    "fim_scan_enabled": {
        "lib": event_fim,
        "description": "Automatic file integration scanning enabled."
    },
    "fim_scan_failed": {
        "lib": event_fim,
        "description": "File integrity scan failed."
    },
    "fim_scan_modified": {
        "lib": event_fim,
        "description": "Auto. file integration scan schedule modified."
    },
    "fim_scan_requested": {
        "lib": event_fim,
        "description": "File integrity scan requested."
    },
    "fim_signature_changed": {
        "lib": event_fim,
        "description": "File integrity object signature changed (DEPRECATED)."
    },
    "fim_target_integrity_changed": {
        "lib": event_fim,
        "description": "File integrity change detected (object added, missing, or changed)."
    },
    "firewall_policy_assigned": {
        "lib": event_fw,
        "description": "Halo firewall policy assigned (Assigned to a server group)."
    },
    "firewall_policy_created": {
        "lib": event_fw,
        "description": "Halo firewall policy created."
    },
    "firewall_policy_deleted": {
        "lib": event_fw,
        "description": "Halo firewall policy deleted."
    },
    "firewall_policy_modified": {
        "lib": event_fw,
        "description": "Halo firewall policy modified."
    },
    "firewall_policy_unassigned": {
        "lib": event_fw,
        "description": "Halo firewall policy unassigned (Removed from a server group)."
    },
    "firewall_restore_requested": {
        "lib": event_fw,
        "description": "Server firewall restore requested."
    },
    "firewall_service_added": {
        "lib": event_fw,
        "description": "Network service added (NW service added to firewalls)."
    },
    "firewall_service_deleted": {
        "lib": event_fw,
        "description": "Network service deleted (NW service removed from fiewalls)."
    },
    "firewall_service_modified": {
        "lib": event_fw,
        "description": "Network service modified (Existing NW service modifiied)."
    },
    "ghostport_close": {
        "lib": event_ghostport,
        "description": "Ghostports session close."
    },
    "ghostport_failure": {
        "lib": event_ghostport,
        "description": "Ghostports login failure."
    },
    "ghostport_provisioning": {
        "lib": event_ghostport,
        "description": "Ghostports provisioning (GhostPorts user created/enabled)."
    },
    "ghostport_success": {
        "lib": event_ghostport,
        "description": "Ghostports login success."
    },
    "halo_login_failure": {
        "lib": event_halo_user,
        "description": "Halo login failure."
    },
    "halo_login_success": {
        "lib": event_halo_user,
        "description": "Halo login success."
    },
    "halo_user_logout": {
        "lib": event_halo_user,
        "description": "Halo logout."
    },
    "halo_user_deactivated": {
        "lib": event_halo_user,
        "description": "Halo user deactivated."
    },
    "halo_user_invited": {
        "lib": event_halo_user,
        "description": "Halo user invited."
    },
    "halo_user_locked": {
        "lib": event_halo_user,
        "description": "Halo user account locked."
    },
    "halo_user_modified": {
        "lib": event_halo_user,
        "description": "Halo user modified."
    },
    "halo_user_reactivated": {
        "lib": event_halo_user,
        "description": "Halo user reactivated."
    },
    "halo_user_reinvited": {
        "lib": event_halo_user,
        "description": "Halo user reinvited."
    },
    "halo_user_unlocked": {
        "lib": event_halo_user,
        "description": "Halo user account unlocked."
    },
    "ip_address_changed": {
        "lib": event_server,
        "description": "Server IP address changed."
    },
    "lids_rule_failed": {
        "lib": event_lids,
        "description": "Log-based intrusion detection rule matched."
    },
    "lids_scan_disabled": {
        "lib": event_lids,
        "description": "Log-based intrusion detection disabled."
    },
    "lids_scan_enabled": {
        "lib": event_lids,
        "description": "Log-based intrusion detection enabled."
    },
    "lids_policy_assigned": {
        "lib": event_lids,
        "description": "Log-based intrusion detection policy assigned."
    },
    "lids_policy_created": {
        "lib": event_lids,
        "description": "Log-based intrusion detection policy created."
    },
    "lids_policy_deleted": {
        "lib": event_lids,
        "description": "Log-based intrusion detection policy deleted."
    },
    "lids_policy_exported": {
        "lib": event_lids,
        "description": "Log-based intrusion detection policy exported."
    },
    "lids_policy_modified": {
        "lib": event_lids,
        "description": "Log-based intrusion detection policy modified."
    },
    "lids_policy_unassigned": {
        "lib": event_lids,
        "description": "Log-based intrusion detection policy unassigned."
    },
    "local_account_activate_request": {
        "lib": event_sam,
        "description": "Local account activation requested."
    },
    "local_account_create_request": {
        "lib": event_sam,
        "description": "Local account creation requested."
    },
    "local_account_delete_request": {
        "lib": event_sam,
        "description": "Local account deactivation requested."
    },
    "local_account_update_request": {
        "lib": event_sam,
        "description": "Local account modification requested."
    },
    "local_account_update_ssh_keys_request": {
        "lib": event_sam,
        "description": "Local account ssh keys update requested."
    },
    "master_account_linked": {
        "lib": event_halo_acct,
        "description": "Master account linked (Halo account linked to master account)."
    },
    "multiple_root_accounts": {
        "lib": event_sam,
        "description": "Multiple root accounts detected (linux)."
    },
    "new_server": {
        "lib": event_server,
        "description": "New server."
    },
    "password_changed": {
        "lib": event_halo_user,
        "description": "Halo password changed."
    },
    "password_config_changed": {
        "lib": event_halo_user,
        "description": "Halo authentication settings modified."
    },
    "password_recovery_requested": {
        "lib": event_halo_user,
        "description": "Halo password recovery requested."
    },
    "password_recovery_request_failed": {
        "lib": event_halo_user,
        "description": "Halo password recovery request failed."
    },
    "password_recovery_success": {
        "lib": event_halo_user,
        "description": "Halo password recovery success."
    },
    "sca_policy_assigned": {
        "lib": event_sca,
        "description": "Configuration policy assigned."
    },
    "sca_policy_created": {
        "lib": event_sca,
        "description": "Configuration polcy created."
    },
    "sca_policy_deleted": {
        "lib": event_sca,
        "description": "Configuration policy deleted."
    },
    "sca_policy_exported": {
        "lib": event_sca,
        "description": "Configuration policy exported."
    },
    "sca_policy_imported": {
        "lib": event_sca,
        "description": "Configuration policy imported."
    },
    "sca_policy_modified": {
        "lib": event_sca,
        "description": "Configuration policy modified."
    },
    "sca_policy_unassigned": {
        "lib": event_sca,
        "description": "Configuration policy unassigned (Removed from a server group)."
    },
    "sca_rule_failed": {
        "lib": event_sca,
        "description": "Configuration rule matched (One or more rule checks failed)."
    },
    "server_account_created": {
        "lib": event_sam,
        "description": "Local account created (linux only)."
    },
    "server_account_deleted": {
        "lib": event_sam,
        "description": "Local account deleted (linux only)."
    },
    "server_deactivated": {
        "lib": event_sam,
        "description": "Server deactivated."
    },
    "server_deleted": {
        "lib": event_sam,
        "description": "Server deleted."
    },
    "server_firewall_modified_locally": {
        "lib": event_fw,
        "description": "Server firewall modified (Modified outside of Halo)."
    },
    "server_missing": {
        "lib": event_server,
        "description": "Server missing (No agent contact with engine)."
    },
    "server_moved": {
        "lib": event_server,
        "description": "Server moved to another group (Moved to another server group)."
    },
    "server_reactivated": {
        "lib": event_server,
        "description": "Server reactivated."
    },
    "server_restarted": {
        "lib": event_server,
        "description": "Server restarted."
    },
    "server_retired": {
        "lib": event_server,
        "description": "Server retired."
    },
    "server_shutdown": {
        "lib": event_server,
        "description": "Server shutdown."
    },
    "server_unretired": {
        "lib": event_server,
        "description": "Server un-retired."
    },
    "session_timeout": {
        "lib": event_halo_portal,
        "description": "Halo session timeout."
    },
    "sms_phone_number_verified": {
        "lib": event_halo_user,
        "description": "SMS phone number verified (For two-factor authentication)."
    },
    "vulnerable_software_package_found": {
        "lib": event_svm,
        "description": "Vulnerable software package found (Software vulnerability scan result)."
    }
}
