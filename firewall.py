import subprocess

def block_ip(ip):
    """
    Blocks the specified IP in Windows Firewall.
    Creates a block rule if it does not already exist.
    """

    rule_name = f"NetworkGuardian_Block_{ip}"

    try:
        # Add firewall rule
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}"
            ],
            capture_output=True,
            text=True,
            check=False
        )

        print(f"[FIREWALL] BLOCKED IP: {ip}")

    except Exception as e:
        print(f"[FIREWALL ERROR] Could not block {ip}: {e}")
