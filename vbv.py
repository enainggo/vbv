import os
import subprocess

# Helper function to run shell commands
def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr.strip()}")
    else:
        print(f"Output: {result.stdout.strip()}")

# Helper function to write to a file with sudo
def sudo_write_file(file_path, content):
    temp_file = "/tmp/temp_file"
    with open(temp_file, 'w') as f:
        f.write(content)
    run_command(f"sudo cp {temp_file} {file_path}")
    run_command(f"sudo rm {temp_file}")

# Initial Access (Gate Entry)
def setup_password_policy():
    print("Setting up password policy...")
    run_command("sudo apt-get update")
    run_command("sudo apt-get install libpam-pwquality -y")
    pam_common_password = "/etc/pam.d/common-password"
    content = "\npassword requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1\n"
    sudo_write_file(pam_common_password, content)
    print(f"Updated {pam_common_password}")

def setup_u2f():
    print("Setting up U2F (YubiKey) authentication...")
    run_command("sudo apt-get install libpam-u2f -y")
    os.makedirs(os.path.expanduser("~/.config/Yubico"), exist_ok=True)
    run_command("pamu2fcfg > ~/.config/Yubico/u2f_keys")
    pam_sshd = "/etc/pam.d/sshd"
    content = "\nauth required pam_u2f.so\n"
    sudo_write_file(pam_sshd, content)
    print(f"Updated {pam_sshd}")

# Behavioral Verification
def setup_behavioral_verification():
    print("Setting up behavioral verification...")
    run_command("sudo apt-get install libpam-script -y")
    pam_common_auth = "/etc/pam.d/common-auth"
    content = "\nauth optional pam_script.so\n"
    sudo_write_file(pam_common_auth, content)
    print(f"Updated {pam_common_auth}")

    user_behavior_script = "/etc/security/user_behavior.sh"
    script_content = """#!/bin/bash
USER_BEHAVIOR_FILE="/var/log/user_behavior.log"
CURRENT_TIME=$(date +%s)
LAST_LOGIN=$(grep "$PAM_USER" "$USER_BEHAVIOR_FILE" | tail -n 1 | cut -d ' ' -f 2)

if [ -z "$LAST_LOGIN" ]; then
  echo "$PAM_USER $CURRENT_TIME" >> "$USER_BEHAVIOR_FILE"
else
  DIFF=$((CURRENT_TIME - LAST_LOGIN))
  if [ "$DIFF" -gt 600 ]; then
    echo "User $PAM_USER failed behavior check" | mail -s "Security Alert" admin@example.com
    exit 1
  else
    echo "$PAM_USER $CURRENT_TIME" >> "$USER_BEHAVIOR_FILE"
  fi
fi
exit 0
"""
    sudo_write_file(user_behavior_script, script_content)
    run_command(f"sudo chmod +x {user_behavior_script}")
    print(f"Created and updated {user_behavior_script}")

# Role-Based Access Control
def setup_rbac():
    print("Setting up role-based access control...")
    run_command("sudo apt-get install libpam-role -y")
    role_conf = "/etc/security/role.conf"
    role_content = """
[admin]
users = user1, user2
permissions = ALL

[user]
users = user3, user4
permissions = /bin/ls, /usr/bin/vim, /usr/bin/ssh
"""
    sudo_write_file(role_conf, role_content)
    pam_common_auth = "/etc/pam.d/common-auth"
    content = "\nauth required pam_role.so config=/etc/security/role.conf\n"
    sudo_write_file(pam_common_auth, content)
    print(f"Created and updated {pam_common_auth}")

# Adaptive Challenges
def setup_adaptive_auth():
    print("Setting up adaptive authentication...")
    adaptive_auth_script = "/etc/security/adaptive_auth.sh"
    script_content = """#!/bin/bash
CURRENT_HOUR=$(date +%H)
USER_IP=$(echo $PAM_RHOST)

if [ "$CURRENT_HOUR" -lt 9 ] || [ "$CURRENT_HOUR" -gt 17 ]; then
  read -p "Enter additional security code: " security_code
  if [ "$security_code" != "expected_code" ]; then
    echo "Adaptive authentication failed: wrong security code" | mail -s "Security Alert" admin@example.com
    exit 1
  fi
fi

if [[ "$USER_IP" != "192.168.1.*" ]]; then
  read -p "Enter location-based security code: " location_code
  if [ "$location_code" != "expected_location_code" ]; then
    echo "Adaptive authentication failed: wrong location code" | mail -s "Security Alert" admin@example.com
    exit 1
  fi
fi

exit 0
"""
    sudo_write_file(adaptive_auth_script, script_content)
    run_command(f"sudo chmod +x {adaptive_auth_script}")
    print(f"Created and updated {adaptive_auth_script}")

# Anomaly Detection and Response
def setup_fail2ban():
    print("Setting up fail2ban for anomaly detection...")
    run_command("sudo apt-get install fail2ban -y")
    jail_local = "/etc/fail2ban/jail.local"
    jail_content = """
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
"""
    sudo_write_file(jail_local, jail_content)
    run_command("sudo systemctl start fail2ban")
    run_command("sudo systemctl enable fail2ban")
    print(f"Created and updated {jail_local}")

def main():
    setup_password_policy()
    setup_u2f()
    setup_behavioral_verification()
    setup_rbac()
    setup_adaptive_auth()
    setup_fail2ban()
    print("All security measures have been set up successfully!")

if __name__ == "__main__":
    main()
