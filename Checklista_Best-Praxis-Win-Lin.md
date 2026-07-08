# Checklista - Best Practices

## Windows

* **RDP Open to the Internet:** Publicly accessible Remote Desktop ports that allow brute-force login attempts from the web.
* **Default Administrator Name:** An active built-in master account named "Administrator," which gives attackers half of the login credentials by default.
* **Simple Passwords:** Local security policies that permit short, weak, or easily guessable passwords.
* **Windows Update Disabled:** A system configuration that blocks automatic security patches, leaving the OS vulnerable to known exploits.
* **Antivirus Turned Off:** Missing or disabled real-time protection from Windows Defender or third-party antimalware software.
* **Unused Shared Folders:** Network shares left open to "Everyone" or legacy project folders that expose data internally.
* **Guest Account Active:** An enabled built-in "Guest" profile that allows unauthenticated users to access the system.
* **Firewall Turned Off:** A disabled Windows Defender Firewall, leaving all network ports completely unprotected.
* **Unused Software Installed:** Unnecessary applications, browsers, or tools left on the system that increase the local attack surface.(e.g `FTP, Telnet, Remote Registry, Print Spooler`)
* **No Screen Lockout:** An idle session timeout policy that allows a server to stay logged in indefinitely when left unattended.

---

## Linux

* **SSH Open to the Internet:** A wide-open port 22 that exposes the server's remote management interface to the entire web.
* **Root Login via SSH:** An SSH configuration (`PermitRootLogin yes`) that allows attackers to target the absolute master account directly over the network.
* **No Automatic Updates:** A lack of automated security patching (like `unattended-upgrades`), leaving software packages vulnerable over time.
* **Firewall Disabled:** An inactive local firewall daemon (`ufw` or `firewalld`) that fails to block unauthorized incoming traffic.
* **Accounts with No Passwords:** Active user accounts configured with blank passwords, allowing instant access to anyone who knows the username.
* **Old Linux Versions:** An operating system distribution that has reached End-of-Life (EOL) and no longer receives critical vendor security updates.
* **Too Many Sudo Users:** An over-permissive `sudoers` configuration that grants full administrative privileges to too many standard user accounts.
* **Unused Open Ports:** Background processes listening on the network for services that are no longer needed or active.
* **Default SSH Banner:** A standard SSH welcome message that leaks the exact operating system and version details to potential outsiders.