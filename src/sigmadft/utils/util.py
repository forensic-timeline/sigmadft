# src/sigmadft/utils/util.py

import ast
import re
from urllib.parse import urlparse
from sigmadft.events.LowLevelEvent import LowLevelEvent


class Utils:
    """Utility functions for extracting information from events - standardized to use LowLevelEvent"""
        
    @staticmethod
    def get_file_path(low_level_event: LowLevelEvent) -> str:
        """Extract file path from the low level event"""
        return low_level_event.path
    
    @staticmethod
    def get_timestamp(low_level_event: LowLevelEvent) -> str:
        """Extract timestamp from the low level event"""
        return low_level_event.date_time_min
    
    @staticmethod
    def get_event_type(low_level_event: LowLevelEvent) -> str:
        """Extract event type from the low level event"""
        return low_level_event.type
    
    @staticmethod
    def get_plugin_name(low_level_event: LowLevelEvent) -> str:
        """Extract plugin name from the low level event"""
        return low_level_event.plugin
    
    @staticmethod
    def get_evidence(low_level_event: LowLevelEvent) -> str:
        """Extract evidence from the low level event"""
        return low_level_event.evidence

    @staticmethod
    def get_browser(low_level_event: LowLevelEvent) -> str:
        """Extract browser information from plugin string"""
        browsers = {
            "firefox": "Mozilla Firefox",
            "chrome": "Chromium based Browser",
            "edge": "Microsoft Edge",
            "safari": "Safari",
        }
        
        # Get plugin from the low level event
        plugin = low_level_event.plugin
        if not plugin:
            return "Unknown Browser"
            
        plugin_lower = plugin.lower()
        for key, value in browsers.items():
            if key in plugin_lower:
                return value
        return "Unknown Browser"

    @staticmethod
    def extract_url(low_level_event: LowLevelEvent) -> str:
        """Extract URL from evidence string"""
        evidence = low_level_event.evidence
            
        # First try to get URL before any parentheses
        url_match = evidence.split(" (")[0].strip()
        if url_match.startswith(("http://", "https://", "www.")):
            return url_match

        # If that fails, try to find URL in the full string
        url_pattern = r'https?://[^\s()"]+'
        match = re.search(url_pattern, evidence)
        if match:
            return match.group(0)

        return ""
    
    @staticmethod
    def extract_domain_from_url(low_level_event: LowLevelEvent) -> str:
        """Extract URL from evidence string"""
        url = Utils.extract_url(low_level_event)
        if url:
            # Parse the URL and extract the domain (netloc)
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Remove 'www.' prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
                
            return domain

        return ""
    
    @staticmethod
    def extract_youtube_video_title(low_level_event: LowLevelEvent) -> str:
        """Extract YouTube video title from evidence string"""
        evidence = low_level_event.evidence 
        
        # Plaso history format: "<URL> (<Title>) [count: N] ..."
        # Take everything between the first " (" after the URL and ") [count:",
        # so titles containing parentheses, e.g. "Mangu (Lyrics) - YouTube", stay intact.
        match = re.search(r'^\S+\s+\((.*?)\)\s+\[count:', evidence)
        if match:
            return match.group(1).strip()

        # Fallback: first parenthesised text
        # Pattern: (Title - YouTube) or (Title)
        title_pattern = r'\(([^)]+(?:\s*-\s*YouTube)?)\)'
        match = re.search(title_pattern, evidence)
        
        if match:
            title = match.group(1)
            return title.strip()
        
        return ""
    
    @staticmethod
    def extract_google_search_term(low_level_event: LowLevelEvent) -> str:
        """Extract search term from Google search URL"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for Google search: q=SEARCH_TERM
        search_match = re.search(r'[?&]q=([^&\s]+)', evidence)
        if search_match:
            search_term = search_match.group(1)
            # URL decode the search term
            search_term = search_term.replace('%20', ' ').replace('%22', '"').replace('%27', "'")
            search_term = search_term.replace('+', ' ')  # Google uses + for spaces
            return search_term
        
        return ""
    
    @staticmethod
    def extract_bing_search_term(low_level_event: LowLevelEvent) -> str:
        """Extract search term from Bing search URL"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for Bing search: q=SEARCH_TERM
        search_match = re.search(r'[?&]q=([^&\s]+)', evidence)
        if search_match:
            search_term = search_match.group(1)
            # URL decode the search term
            search_term = search_term.replace('%20', ' ').replace('%22', '"').replace('%27', "'")
            search_term = search_term.replace('+', ' ')  # Bing also uses + for spaces
            search_term = search_term.replace('%2B', '+')  # Handle encoded plus signs
            return search_term
        
        return ""
    
    @staticmethod
    def extract_useradd_activity_type(low_level_event: LowLevelEvent) -> str:
        """Extract the type of useradd activity (new user, new group, failed)"""
        evidence = low_level_event.evidence
        
        if 'new user:' in evidence:
            return "User Created"
        elif 'new group:' in evidence:
            return "Group Created"
        elif 'failed adding user' in evidence:
            return "User Creation Failed"
        elif re.search(r'COMMAND=\S*useradd\b', evidence):
            return "User Add Command"

        return "Unknown Activity"
    
    @staticmethod
    def extract_useradd_username(low_level_event: LowLevelEvent) -> str:
        """Extract username from useradd log entry"""
        evidence = low_level_event.evidence
        
        # Pattern for new user: name=username
        user_match = re.search(r'name=([^\s]+)', evidence)
        if user_match:
            return user_match.group(1)
        
        # Pattern for failed adding user 'username'
        failed_match = re.search(r"failed adding user '([^']+)'", evidence)
        if failed_match:
            return failed_match.group(1)

        # Pattern for sudo command: COMMAND=/usr/sbin/useradd [options] username
        command_match = re.search(r'COMMAND=\S*useradd\b.*\s([^\s]+)\s*$', evidence)
        if command_match:
            return command_match.group(1)

        return ""
    
    @staticmethod
    def extract_useradd_creator(low_level_event: LowLevelEvent) -> str:
        """Extract the user who created the new user (from sudo logs)"""
        evidence = low_level_event.evidence
        
        # Look for sudo log pattern: username : TTY=pts/0 ; PWD=/path ; USER=root ; COMMAND=/usr/sbin/useradd
        sudo_match = re.search(r'(\w+)\s*:\s*TTY=.*COMMAND=\S*useradd\b', evidence)
        if sudo_match:
            return sudo_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_uid(low_level_event: LowLevelEvent) -> str:
        """Extract UID from useradd log entry"""
        evidence = low_level_event.evidence
        
        uid_match = re.search(r'UID=(\d+)', evidence)
        if uid_match:
            return uid_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_gid(low_level_event: LowLevelEvent) -> str:
        """Extract GID from useradd log entry"""
        evidence = low_level_event.evidence
        
        gid_match = re.search(r'GID=(\d+)', evidence)
        if gid_match:
            return gid_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_home(low_level_event: LowLevelEvent) -> str:
        """Extract home directory from useradd log entry"""
        evidence = low_level_event.evidence
        
        home_match = re.search(r'home=([^\s]+)', evidence)
        if home_match:
            return home_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_shell(low_level_event: LowLevelEvent) -> str:
        """Extract shell from useradd log entry"""
        evidence = low_level_event.evidence
        
        shell_match = re.search(r'shell=([^\s]+)', evidence)
        if shell_match:
            return shell_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_exit_code(low_level_event: LowLevelEvent) -> str:
        """Extract exit code from failed useradd attempts"""
        evidence = low_level_event.evidence
        
        exit_code_match = re.search(r'exit code:\s*(\d+)', evidence)
        if exit_code_match:
            return exit_code_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_usermod_activity_type(low_level_event: LowLevelEvent) -> str:
        """Extract the type of usermod activity"""
        evidence = low_level_event.evidence
        
        if 'add' in evidence and 'to group' in evidence:
            if 'shadow group' in evidence:
                return "Added to Shadow Group"
            else:
                return "Added to Group"
        elif 'COMMAND=' in evidence and 'usermod' in evidence:
            return "User Modification Command"
        elif 'usermod' in evidence:
            return "User Modified"
        
        return "Unknown Modification"
    
    @staticmethod
    def extract_usermod_target_user(low_level_event: LowLevelEvent) -> str:
        """Extract the target username being modified"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: add 'username' to group 'groupname'
        add_group_match = re.search(r"add '([^']+)' to (?:shadow )?group", evidence)
        if add_group_match:
            return add_group_match.group(1)
        
        # Pattern for sudo command: COMMAND=/usr/sbin/usermod -aG group username
        command_match = re.search(r'COMMAND=.*usermod.*\s+([^\s]+)', evidence)
        if command_match:
            return command_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_usermod_creator(low_level_event: LowLevelEvent) -> str:
        """Extract the user who executed the usermod command"""
        evidence = low_level_event.evidence
        
        # Look for sudo log pattern: username : TTY=pts/0 ; PWD=/path ; USER=root ; COMMAND=/usr/sbin/usermod
        sudo_match = re.search(r'(\w+)\s*:\s*TTY=.*COMMAND=.*usermod', evidence)
        if sudo_match:
            return sudo_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_usermod_group(low_level_event: LowLevelEvent) -> str:
        """Extract the group name from usermod activity"""
        evidence = low_level_event.evidence
        
        # Pattern for: add 'username' to group 'groupname'
        group_match = re.search(r"to (?:shadow )?group '([^']+)'", evidence)
        if group_match:
            return group_match.group(1)
        
        # Pattern for command arguments: -aG groupname
        command_group_match = re.search(r'-aG\s+([^\s]+)', evidence)
        if command_group_match:
            return command_group_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_usermod_group_type(low_level_event: LowLevelEvent) -> str:
        """Extract whether it's a regular or shadow group"""
        evidence = low_level_event.evidence
        
        if 'shadow group' in evidence:
            return "shadow"
        elif 'to group' in evidence:
            return "regular"
        
        return ""
    
    @staticmethod
    def extract_usermod_command_args(low_level_event: LowLevelEvent) -> str:
        """Extract the full command arguments from usermod command"""
        evidence = low_level_event.evidence
        
        # Extract arguments from COMMAND=/usr/sbin/usermod [args]
        command_match = re.search(r'COMMAND=.*usermod\s+(.+)', evidence)
        if command_match:
            return command_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_failure_type(low_level_event: LowLevelEvent) -> str:
        """Extract the type of authentication failure"""
        evidence = low_level_event.evidence
        
        if 'Failed password for invalid user' in evidence:
            return "Failed Password (Invalid User)"
        elif 'Failed password for' in evidence:
            return "Failed Password"
        elif 'authentication failure' in evidence:
            return "Authentication Failure"
        elif 'PAM' in evidence and 'authentication failure' in evidence:
            return "PAM Authentication Failure"
        elif 'Disconnected from' in evidence and 'preauth' in evidence:
            return "Disconnected (Preauth)"
        
        return "Unknown Auth Failure"
    
    @staticmethod
    def extract_auth_target_user(low_level_event: LowLevelEvent) -> str:
        """Extract the target username from authentication attempt"""
        evidence = low_level_event.evidence
        
        # Pattern for: Failed password for [invalid user] username
        failed_password_match = re.search(r'Failed password for (?:invalid user )?([^\s]+)', evidence)
        if failed_password_match:
            return failed_password_match.group(1)
        
        # Pattern for: Disconnected from invalid user username
        disconnected_match = re.search(r'Disconnected from (?:invalid user )?([^\s]+)', evidence)
        if disconnected_match:
            return disconnected_match.group(1)
        
        # Pattern for PAM auth failure: user=username
        pam_match = re.search(r'user=([^\s]+)', evidence)
        if pam_match:
            return pam_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_source_ip(low_level_event: LowLevelEvent) -> str:
        """Extract source IP address from authentication attempt"""
        evidence = low_level_event.evidence
        
        # Pattern for: from IP_ADDRESS port
        ip_port_match = re.search(r'from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', evidence)
        if ip_port_match:
            return ip_port_match.group(1)
        
        # Pattern for: rhost=IP_ADDRESS
        rhost_match = re.search(r'rhost=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', evidence)
        if rhost_match:
            return rhost_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_source_port(low_level_event: LowLevelEvent) -> str:
        """Extract source port from authentication attempt"""
        evidence = low_level_event.evidence
        
        # Pattern for: from IP port PORT_NUMBER
        port_match = re.search(r'port (\d+)', evidence)
        if port_match:
            return port_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_service(low_level_event: LowLevelEvent) -> str:
        """Extract the service/daemon that handled the authentication"""
        evidence = low_level_event.evidence
        
        # Extract service from log format: [service_name pid: ####]
        service_match = re.search(r'\[([^\s\]]+)', evidence)
        if service_match:
            return service_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_user_validity(low_level_event: LowLevelEvent) -> str:
        """Extract whether the user is valid or invalid"""
        evidence = low_level_event.evidence
        
        if 'invalid user' in evidence:
            return "invalid"
        elif 'Failed password for' in evidence or 'authentication failure' in evidence:
            return "valid"
        
        return ""
    
    @staticmethod
    def extract_auth_tty(low_level_event: LowLevelEvent) -> str:
        """Extract TTY information from authentication attempt"""
        evidence = low_level_event.evidence
        
        # Pattern for: tty=TTY_VALUE
        tty_match = re.search(r'tty=([^\s]+)', evidence)
        if tty_match:
            return tty_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_remote_host(low_level_event: LowLevelEvent) -> str:
        """Extract remote host information"""
        evidence = low_level_event.evidence
        
        # Pattern for: rhost=HOSTNAME (usually same as IP for direct connections)
        rhost_match = re.search(r'rhost=([^\s]+)', evidence)
        if rhost_match and rhost_match.group(1):
            return rhost_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_session_target_user(low_level_event: LowLevelEvent) -> str:
        """Extract the target user for whom the session is opened"""
        evidence = low_level_event.evidence
        
        
        # Pattern for: session opened for user USERNAME by
        target_match = re.search(r'session opened for user ([^\s]+)', evidence)
        if target_match:
            return target_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_session_executor_user(low_level_event: LowLevelEvent) -> str:
        """Extract the user who initiated the session"""
        evidence = low_level_event.evidence
        
        
        # Pattern for: by USERNAME(uid=####)
        executor_match = re.search(r'by ([^\s\(]+)(?:\(uid=\d+\))?', evidence)
        if executor_match:
            executor = executor_match.group(1)
            # Handle cases where 'by' is followed by (uid=###) without username
            if executor.startswith('(uid='):
                return "system"
            return executor
        
        # If no specific user mentioned, it's likely a system-initiated session
        if 'by (uid=' in evidence:
            return "system"
        
        return ""
    
    @staticmethod
    def extract_session_service_name(low_level_event: LowLevelEvent) -> str:
        """Extract the service that opened the session"""
        evidence = low_level_event.evidence
        
        # Extract service from log format: [service_name pid: ####]
        service_match = re.search(r'\[([^\s\]]+)', evidence)
        if service_match:
            return service_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_session_executor_uid(low_level_event: LowLevelEvent) -> str:
        """Extract the UID of the user who initiated the session"""
        evidence = low_level_event.evidence
        
        
        # Pattern for: by username(uid=####) or by (uid=####)
        uid_match = re.search(r'uid=(\d+)', evidence)
        if uid_match:
            return uid_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_session_type(low_level_event: LowLevelEvent) -> str:
        """Extract the type of session based on the service"""
        
        service = Utils.extract_session_service_name(low_level_event)
        
        if service == 'sudo':
            return "Privilege Escalation"
        elif service == 'sshd':
            return "SSH Login"
        elif 'systemd-logind' in service or 'gdm' in service:
            return "System Login"
        elif service == 'su':
            return "User Switch"
        elif service == 'cron' or 'CRON' in service:
            return "Scheduled Task"
        else:
            return "Other Session"
        
    @staticmethod
    def extract_webshell_command(low_level_event: LowLevelEvent) -> str:
        """Extract the command executed in web shell request"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: ?cmd=COMMAND or &cmd=COMMAND
        cmd_match = re.search(r'[?&]cmd=([^&\s]+)', evidence)
        if cmd_match:
            command = cmd_match.group(1)
            # URL decode basic characters
            command = command.replace('%20', ' ').replace('%2F', '/').replace('%3D', '=')
            return command
        
        # Pattern for: ?command=COMMAND
        command_match = re.search(r'[?&]command=([^&\s]+)', evidence)
        if command_match:
            command = command_match.group(1)
            command = command.replace('%20', ' ').replace('%2F', '/').replace('%3D', '=')
            return command
        
        return ""
    
    @staticmethod
    def extract_webshell_php_file(low_level_event: LowLevelEvent) -> str:
        """Extract the PHP file name from the request"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: GET /filename.php or POST /filename.php
        php_match = re.search(r'(?:GET|POST)\s+(/[^\s?]+\.php)', evidence)
        if php_match:
            return php_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_webshell_source_ip(low_level_event: LowLevelEvent) -> str:
        """Extract source IP address from HTTP request"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: from: IP_ADDRESS
        ip_match = re.search(r'from:\s+([^\s]+)', evidence)
        if ip_match:
            return ip_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_webshell_http_method(low_level_event: LowLevelEvent) -> str:
        """Extract HTTP method from the request"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: http_request: METHOD
        method_match = re.search(r'http_request:\s+(GET|POST|PUT|DELETE|HEAD|OPTIONS)', evidence)
        if method_match:
            return method_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_webshell_response_code(low_level_event: LowLevelEvent) -> str:
        """Extract HTTP response code"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: code: ###
        code_match = re.search(r'code:\s+(\d+)', evidence)
        if code_match:
            return code_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_webshell_user_agent(low_level_event: LowLevelEvent) -> str:
        """Extract User-Agent from the request"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: user_agent: AGENT_STRING
        ua_match = re.search(r'user_agent:\s+(.+)', evidence)
        if ua_match:
            return ua_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_webshell_attack_type(low_level_event: LowLevelEvent) -> str:
        """Classify the type of web shell attack"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        command = Utils.extract_webshell_command(low_level_event).lower()
        
        if any(func in command for func in ['eval', 'base64_decode', 'system', 'exec', 'shell_exec']):
            return "Code Injection"
        elif any(cmd in command for cmd in ['whoami', 'uname', 'systeminfo', 'ifconfig', 'netstat']):
            return "System Reconnaissance"
        elif any(cmd in command for cmd in ['ls', 'dir', 'pwd', 'cat']):
            return "File System Reconnaissance"
        elif any(cmd in command for cmd in ['ps', 'tasklist']):
            return "Process Reconnaissance"
        elif any(cmd in command for cmd in ['wget', 'curl', 'nc', 'netcat']):
            return "Network Activity"
        elif any(cmd in command for cmd in ['chmod', 'chown', 'passwd', 'useradd', 'sudo']):
            return "Privilege Escalation"
        elif any(cmd in command for cmd in ['ping']):
            return "Network Reconnaissance"
        else:
            return "Command Execution"

    # ------------------------------------------------------------------
    # Web requests (Plaso "text/apache_access" parser) and decoded payloads
    # ------------------------------------------------------------------
    # Message example:
    #   http_request: GET /path.php?wp_meta=WyJpZCJd HTTP/1.1 from: 172.17.130.196
    #   code: 200 user_agent: python-requests/2.27.1

    @staticmethod
    def extract_http_request_uri(low_level_event: LowLevelEvent) -> str:
        """Extract the requested URI (path and query string) of an HTTP request"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        uri_match = re.search(r'http_request:\s+\S+\s+(\S+)', evidence)
        return uri_match.group(1) if uri_match else ""

    @staticmethod
    def extract_decoded_payload(low_level_event: LowLevelEvent) -> str:
        """Extract the payload decoded by -d/--decode (the text of [DECODED: ...])"""
        return getattr(low_level_event, 'decoded_payload', None) or ""

    # ------------------------------------------------------------------
    # sudo (Plaso "text/syslog", "text/syslog_traditional", "systemd_journal")
    # ------------------------------------------------------------------
    # Message examples:
    #   [sudo] phopkins : TTY=pts/1 ; PWD=/var/www/... ; USER=root ; COMMAND=/bin/cat /etc/shadow
    #   kuncen [sudo  pid: 11629] testuser : TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow

    @staticmethod
    def extract_sudo_user(low_level_event: LowLevelEvent) -> str:
        """Extract the user who ran sudo"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        user_match = re.search(r'(\S+)\s+:\s+TTY=', evidence)
        return user_match.group(1) if user_match else ""

    @staticmethod
    def extract_sudo_tty(low_level_event: LowLevelEvent) -> str:
        """Extract the terminal sudo was run from"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        tty_match = re.search(r'TTY=([^\s;]+)', evidence)
        return tty_match.group(1) if tty_match else ""

    @staticmethod
    def extract_sudo_pwd(low_level_event: LowLevelEvent) -> str:
        """Extract the working directory sudo was run from"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        pwd_match = re.search(r'PWD=([^;]+?)\s*;', evidence)
        return pwd_match.group(1) if pwd_match else ""

    @staticmethod
    def extract_sudo_run_as(low_level_event: LowLevelEvent) -> str:
        """Extract the user the sudo command runs as"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        user_match = re.search(r';\s*USER=([^\s;]+)', evidence)
        return user_match.group(1) if user_match else ""

    @staticmethod
    def extract_sudo_command(low_level_event: LowLevelEvent) -> str:
        """Extract the command executed with sudo"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        command_match = re.search(r'COMMAND=(.+)$', evidence)
        return command_match.group(1).strip() if command_match else ""

    # ------------------------------------------------------------------
    # Logins (sshd, systemd-logind, PAM)
    # ------------------------------------------------------------------
    # Message examples:
    #   [sshd] [943610]: Accepted password for root from 243.23.54.175 port 37190 ssh2
    #   [systemd-logind  pid: 623] New session 44433 of user root.
    #   [sshd] [951322]: Failed password for root from 71.238.128.110 port 54700 ssh2
    #   [sshd  pid: 10808] pam_unix(sshd:auth): authentication failure; ... rhost=127.0.0.1  user=root

    @staticmethod
    def extract_login_user(low_level_event: LowLevelEvent) -> str:
        """Extract the user of a login or login attempt"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        patterns = [
            r'Accepted \S+ for (\S+)',
            r'New session \S+ of user ([^\s.]+)',
            r'Failed password for (?:invalid user )?(\S+)',
            r'Invalid user (\S+)',
            r'authentication failure;.*\buser=(\S+)',
        ]
        for pattern in patterns:
            user_match = re.search(pattern, evidence)
            if user_match:
                return user_match.group(1)
        return ""

    @staticmethod
    def extract_generic_target_user(low_level_event: LowLevelEvent) -> str:
        """Extract the user account an auth/syslog line is about (generic, any service).

        Used by the Sigma adapter's generic keys. Patterns are tried in order;
        for sudo the invoking user is returned (the run-as user is USER=).
        """
        evidence = getattr(low_level_event, 'evidence', '') or ''
        sudo_user = Utils.extract_sudo_user(low_level_event)
        if sudo_user:
            return sudo_user
        patterns = [
            r'(?:Accepted|Failed) \S+ for (?:invalid user )?(\S+)',
            r'Invalid user (\S+)',
            r'Disconnected from (?:invalid |authenticating )?user (\S+)',
            r'New session \S+ of user ([^\s.]+)',
            r'session (?:opened|closed) for user (\S+)',
            r'password changed for (\S+)',
            r'(?:new user|delete user|change user)[:\s]+(?:name=)?\'?([^\s\',]+)',
            r'\buser=([^\s,]+)',
        ]
        for pattern in patterns:
            user_match = re.search(pattern, evidence)
            if user_match:
                return user_match.group(1)
        return ""

    @staticmethod
    def extract_login_method(low_level_event: LowLevelEvent) -> str:
        """Extract how the user logged in (password, publickey, session)"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        method_match = re.search(r'Accepted (\S+) for', evidence)
        if method_match:
            return method_match.group(1)
        if 'New session' in evidence:
            return "session"
        return ""

    # ------------------------------------------------------------------
    # Account management (passwd, userdel)
    # ------------------------------------------------------------------
    # Message examples:
    #   [passwd] [951308]: pam_unix(passwd:chauthtok): password changed for webadmin_cyberpanel
    #   [userdel  pid: 1234] delete user 'bob'

    @staticmethod
    def extract_password_change_user(low_level_event: LowLevelEvent) -> str:
        """Extract the user whose password was changed"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        user_match = re.search(r'password (?:changed|updated|reset) for (\S+)', evidence)
        return user_match.group(1) if user_match else ""

    @staticmethod
    def extract_password_change_action(low_level_event: LowLevelEvent) -> str:
        """Extract the password action (changed, updated, reset)"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        action_match = re.search(r'password (changed|updated|reset)', evidence)
        return action_match.group(1) if action_match else ""

    @staticmethod
    def extract_userdel_username(low_level_event: LowLevelEvent) -> str:
        """Extract the deleted user (or the user owning a removed group)"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        user_match = re.search(r"(?:delete|deleted|remove|removed) user '?([^'\s]+)", evidence)
        if user_match:
            return user_match.group(1)
        group_match = re.search(r"removed (?:shadow )?group '([^']+)'", evidence)
        return group_match.group(1) if group_match else ""

    @staticmethod
    def extract_userdel_activity_type(low_level_event: LowLevelEvent) -> str:
        """Classify the user deletion log line"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        if 'shadow group' in evidence:
            return "Shadow Group Removed"
        if re.search(r'(?:delete|deleted|remove|removed) user', evidence):
            return "User Deleted"
        return ""

    # Message example (permission denied):
    #   [python3  pid: 6020] ... file '/run/ubuntu-advantage//aptnews.json' couldn't be
    #   accessed by user '_apt'. - pkgAcquire::Run (13: Permission denied)

    @staticmethod
    def extract_permission_denied_target(low_level_event: LowLevelEvent) -> str:
        """Extract the path that could not be accessed (first quoted or bare absolute path)"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        path_match = (re.search(r"['\"](/[^'\"]+)['\"]", evidence)
                      or re.search(r'(?<![\w.])(/[^\s:;,()]+)', evidence))
        return path_match.group(1) if path_match else ""

    @staticmethod
    def extract_permission_denied_user(low_level_event: LowLevelEvent) -> str:
        """Extract the user that was denied access, if logged"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        user_match = re.search(r"by user '([^']+)'", evidence)
        return user_match.group(1) if user_match else ""

    # ------------------------------------------------------------------
    # Windows Prefetch (Plaso "prefetch" parser)
    # ------------------------------------------------------------------
    # Message example:
    #   Prefetch [MSEDGE.EXE] was executed - run count 3 path hints:
    #   \PROGRAM FILES (X86)\MICROSOFT\EDGE\APPLICATION\MSEDGE.EXE
    #   hash: 0xF6B373B3 volume: 1 [serial number: ...  device path: ...]

    @staticmethod
    def extract_win_prefetch_process_name(low_level_event: LowLevelEvent) -> str:
        """Executable name recorded in a Prefetch entry, e.g. MSEDGE.EXE"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        name_match = re.search(r'Prefetch \[([^\]]+)\] was executed', evidence)
        return name_match.group(1) if name_match else ""

    @staticmethod
    def extract_win_prefetch_process_path(low_level_event: LowLevelEvent) -> str:
        """Executable path from the Prefetch path hints"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        path_match = re.search(r'path hints: (.+?) hash:', evidence)
        return path_match.group(1).strip() if path_match else ""

    @staticmethod
    def extract_win_prefetch_run_count(low_level_event: LowLevelEvent) -> str:
        """Run count stored in the Prefetch file"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        count_match = re.search(r'was executed - run count (\d+)', evidence)
        return count_match.group(1) if count_match else ""

    # ---- Windows Security event 4688 (A new process has been created) ----
    # Plaso winevtx message: "[4688 / 0x1250] Provider identifier: {...} Source Name:
    # Microsoft-Windows-Security-Auditing Strings: ['v0'  'v1'  ...] Computer Name: ..."
    # Strings follow the EventData order documented by Microsoft (version 2):
    # 0 SubjectUserSid, 1 SubjectUserName, 2 SubjectDomainName, 3 SubjectLogonId,
    # 4 NewProcessId, 5 NewProcessName, 6 TokenElevationType, 7 ProcessId,
    # 8 CommandLine, 9 TargetUserSid, 10 TargetUserName, 11 TargetDomainName,
    # 12 TargetLogonId, 13 ParentProcessName, 14 MandatoryLabel
    @staticmethod
    def _win_evtx_strings(low_level_event: LowLevelEvent) -> list:
        """Parse the Strings list of a Plaso winevtx message into a list of values"""
        evidence = getattr(low_level_event, 'evidence', '') or ''
        block = re.search(r"Strings: \[(.*)\] Computer Name:", evidence, re.DOTALL)
        if not block:
            return []
        values = []
        # Each value is a Python-repr string literal ('...' or "..."), e.g. 'C:\\Windows\\explorer.exe'
        for m in re.finditer(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", block.group(1)):
            try:
                values.append(ast.literal_eval(m.group(0)))
            except (ValueError, SyntaxError):
                values.append(m.group(0)[1:-1])
        return values

    @staticmethod
    def _win_evtx_string_at(low_level_event: LowLevelEvent, index: int) -> str:
        values = Utils._win_evtx_strings(low_level_event)
        value = values[index] if index < len(values) else ""
        return "" if value == "-" else value

    @staticmethod
    def extract_win_4688_new_process_name(low_level_event: LowLevelEvent) -> str:
        """NewProcessName: full path of the created process"""
        return Utils._win_evtx_string_at(low_level_event, 5)

    @staticmethod
    def extract_win_4688_creator_process_name(low_level_event: LowLevelEvent) -> str:
        """ParentProcessName (Creator Process Name, event version 2)"""
        return Utils._win_evtx_string_at(low_level_event, 13)

    @staticmethod
    def extract_win_4688_command_line(low_level_event: LowLevelEvent) -> str:
        """CommandLine (empty unless 'Include command line in process creation events' is enabled)"""
        return Utils._win_evtx_string_at(low_level_event, 8)

    @staticmethod
    def extract_win_4688_subject_user(low_level_event: LowLevelEvent) -> str:
        """Creator Subject as DOMAIN\\Account"""
        user = Utils._win_evtx_string_at(low_level_event, 1)
        domain = Utils._win_evtx_string_at(low_level_event, 2)
        return f"{domain}\\{user}" if domain and user else user

    @staticmethod
    def extract_win_4688_token_elevation_type(low_level_event: LowLevelEvent) -> str:
        """TokenElevationType mapped to its documented meaning"""
        value = Utils._win_evtx_string_at(low_level_event, 6)
        mapping = {
            '%%1936': 'Type 1 (full token)',
            '%%1937': 'Type 2 (elevated token)',
            '%%1938': 'Type 3 (limited token)',
        }
        return mapping.get(value, value)
