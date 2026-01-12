**SSH (Secure Shell)** is a cryptographic network protocol used to securely access and manage a remote computer over an unsecured network. It was developed as a secure replacement for older, unencrypted protocols like **Telnet** and **FTP**.

The basic syntax for connecting is: `ssh username@remote_host_address`
- **Example:** `ssh john@192.168.1.50`
- **With a custom port:** `ssh -p 2222 john@192.168.1.50`
- **Run a remote command**: `ssh user@host "whoami"` 
- **Copying a file (SCP):** `scp localfile.txt john@remote:/path/to/destination`
## Key Features
- **Encryption:** All data sent over the connection (including passwords) is encrypted, protecting it from "packet sniffing" or eavesdropping.
- **Authentication:** Verifies the identity of both the server and the user to prevent "man-in-the-middle" attacks.
- **Port 22:** By default, SSH listens on **TCP port 22**.
- **Data Integrity:** Uses hashing algorithms (like SHA-2) to ensure that data is not tampered with during transit.
## How it Works (The Handshake)
When you connect to a server, SSH goes through a multi-stage process:
1. **TCP Handshake:** A standard connection is established between the client and server.
2. **Negotiation:** Both sides agree on which encryption and hashing versions to use.
3. **Key Exchange (Diffie-Hellman):** They securely generate a "shared secret" key to encrypt the session. This happens without actually sending the key over the network.
4. **Authentication:** The server verifies the user via a password or, more securely, **SSH Keys**.
## Authentication Methods
| **Method**   | **Description**                                                                                            | **Security Level**                       |
| ------------ | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| **Password** | Standard username and password login.                                                                      | **Moderate** (vulnerable to brute-force) |
| **SSH Keys** | Uses a cryptographic pair: a **Public Key** (on the server) and a **Private Key** (on your local machine). | **High** (recommended)                   |
## SSH Key based auth
SSH Key Authentication relies on **Asymmetric Cryptography** (or Public-Key Cryptography).
### Key Components
- **Identity Key (Private Key):** The secret half of the asymmetric pair, typically stored on the client in `~/.ssh/id_rsa` or `~/.ssh/id_ed25519`. It must have restricted filesystem permissions (usually `600`).
- **Authorized Key (Public Key):** The non-secret half, appended to the `~/.ssh/authorized_keys` file on the remote server.
- **Passphrase:** An optional string used to encrypt the private key at rest (using a symmetric cipher like **AES**) (requiring "something you know" to unlock "something you have").
- **Key Fingerprint:** A unique hash (e.g., **SHA256**) of the public key used to verify identities quickly without comparing the entire key string.
### The Authentication Flow (Challenge-Response)
Rather than sending the private key to the server, SSH uses a **Challenge-Response** mechanism to prove ownership.
1. **Identity Offer:** The client sends the **Public Key ID** (or the public key itself) to the server, requesting to authenticate with it.
2. **Key Validation:** The server checks its `authorized_keys` file for a match. If found, it generates a **Random Challenge** (a unique blob of data).
3. **The Challenge:** The server encrypts this challenge using the user's **Public Key** and sends the ciphertext to the client.
4. **The Decryption:** The client decrypts the challenge using its local **Private Key** to retrieve the original random data.
5. **The Signature:** The client combines this decrypted data with the **Session ID** (negotiated during the initial Diffie-Hellman exchange) and signs it using its private key to create a **Digital Signature**.
6. **Verification:** The server uses the public key to verify the signature. If the signature is valid, it proves the client possesses the matching private key, and the session is authenticated.

### Algorithms used
| **Algorithm** | **Technical Basis**                               | **Key Size**     | **Recommended Status**                   |
| ------------- | ------------------------------------------------- | ---------------- | ---------------------------------------- |
| **Ed25519**   | EdDSA (Edwards-curve Digital Signature Algorithm) | 256 bits         | **Best** (Fast, secure, small keys)      |
| **ECDSA**     | Elliptic Curve Digital Signature Algorithm        | 256/384/521 bits | **Good** (Modern, but NIST-standardized) |
| **RSA**       | Integer Factorization (Prime numbers)             | 2048 - 4096 bits | **Legacy** (Use 3072-bit or higher)      |
| **DSA**       | Discrete Logarithm Problem                        | 1024 - 4096 bits | **Deprecated** (Insecure/Weak)           |
### Generating SSH keys
The **Ed25519** algorithm is the current industry standard because it is faster and more secure than RSA.
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```
- `-t ed25519`: Specifies the **Cryptographic Algorithm Type**. Ed25519 uses Elliptic Curve cryptography.
- `-C "comment"`: Adds a **Metadata Label** (usually an email) to the end of the public key file to help you identify it later.
You will be prompted to select a file location (accept the default `~/.ssh/id_rsa`) and enter a **passphrase** for extra security. Using a passphrase is recommended, though it can be left empty for automation purposes.

Once generated, two files are created in your `~/.ssh/` directory: `id_ed25519` the private key and `id_ed25519.pub` the public key

If you are connecting to a very old legacy server that doesn't support Ed25519, use **RSA** with a minimum of 4096 bits:
```bash
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

### Transfering keys
To transfer your public key to a remote server, you use the **Key Exchange** process. This ensures that your public key is placed in the correct location with the required filesystem permissions.

The most reliable way to do this is using the `ssh-copy-id` script. It automatically handles logging in, creating the `.ssh` directory if it doesn't exist, and appending your key to the `authorized_keys` file.
```
ssh-copy-id -i ~/.ssh/id_ed25519.pub username@remote_host
```
- `-i`: Specifies the **Identity File** (the public key) you wish to upload.
- **Result:** Your public key is appended to `~/.ssh/authorized_keys` on the server.

OR using scp:
`scp id_rsa.pub root@homeservername:/home/username/.ssh/authorised_keys`
### Advanced Management Terms
- **SSH Agent:** A background process (`ssh-agent`) that holds decrypted identity keys in memory, allowing for **Single Sign-On (SSO)** across multiple sessions without re-entering passphrases.
	- **To start the agent:** `eval "$(ssh-agent -s)"`
	- **To add your key:** `ssh-add ~/.ssh/id_ed25519`
    - _You only type the passphrase once here. Future SSH connections in that session will be automatic_
- **Agent Forwarding:** A mechanism (`ssh -A`) that allows a remote server to use your local SSH agent to authenticate against a third machine (e.g., jumping from a Bastion host to a private DB).
- **Known Hosts:** A file (`~/.ssh/known_hosts`) on the client that stores the **Host Keys** of servers to prevent Man-in-the-Middle (MITM) attacks by ensuring the server identity hasn't changed.
- **`ssh_config` (Client):** Located at `~/.ssh/config`. Allows you to create **Aliases** for servers, pre-define ports, and specify which key to use for which host.
- **`sshd_config` (Server):** The "Daemon" configuration. Controls security policies like `PermitRootLogin` or `MaxAuthTries`.

## sshd
**sshd** (Secure Shell Daemon) is the server-side software process that listens for incoming SSH connections. While `ssh` is the tool you use to connect _out_, `sshd` is the "gatekeeper" waiting on the server to handle those requests.
### Architectural Role
`sshd` operates as a **Master Process** that typically runs with root privileges. Its primary lifecycle looks like this:
1. **Listen:** It sits on a network socket (default **TCP Port 22**).
2. **Fork:** When a connection request arrives, the master process **forks** a dedicated **Child Process**.
3. **Privilege Separation:** The child process handles the specific session. Modern `sshd` uses "Privilege Separation," where the code that handles unauthenticated network data runs as an unprivileged user to minimize the impact of potential exploits.
### Core Configuration (`sshd_config`)
The daemon is managed by a configuration file located at `/etc/ssh/sshd_config`.
> **Note:** Do not confuse this with `ssh_config`, which is for the client.

| **Directive**                | **Technical Purpose**                                                                                                                                                                 | **Recommended Setting**                                |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| **`Port`**                   | The TCP port the daemon binds to.                                                                                                                                                     | `22` (or a high port to reduce bot spam)               |
| **`PermitRootLogin`**        | Controls if the `root` user can log in via SSH.                                                                                                                                       | `no` or `prohibit-password`                            |
| **`PasswordAuthentication`** | Whether to allow standard passwords.                                                                                                                                                  | `no` (forces SSH keys)                                 |
| **`MaxAuthTries`**           | Limits login attempts before dropping the connection.                                                                                                                                 | `3`                                                    |
| **`AllowUsers`**             | An **Account Whitelist**; only specified users can log in.                                                                                                                            | `user1 user2`                                          |
| KexAlgorithms                | Restricts the **Key Exchange** to specific algorithms.                                                                                                                                | `curve25519-sha256@libssh.org`                         |
| Ciphers                      | Specifies the **Symmetric Encryption** used for the session data. It removes legacy ciphers like 3DES or Blowfish.                                                                    | `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com` |
| PubkeyAuthentication         | Enables the **SSH-USERAUTH** layer to accept digital signatures. The server will attempt to match a client's private key signature against the entries in the `authorized_keys` file. | `yes`                                                  |

### Management Commands
To manage the `sshd` service on modern Linux systems, you use `systemctl`:
- **Start sshd**: `systemctl start sshd`
- **Check Status:** `systemctl status sshd`
- **Restart (Apply Changes):** `systemctl restart sshd`
- **Syntax Check:** `sshd -t`
    - _Always run this before restarting!_ It tests your config file for errors so you don't accidentally lock yourself out of a remote server with a broken configuration.
### Logging and Security
`sshd` sends its event logs to the system logger (syslog). You can monitor authentication attempts in real-time:
- **Debian/Ubuntu:** `tail -f /var/log/auth.log`
- **RHEL/CentOS/Fedora:** `tail -f /var/log/secure`

**Intrusion Prevention:** Because `sshd` is a high-value target, it is often paired with **Fail2Ban**, which parses these logs and uses `iptables` or `nftables` to automatically block IP addresses that show brute-force behavior.

---
## The Protocol Stack
The SSH protocol is logically divided into three hierarchical layers that sit on top of **TCP/IP**.
- **Transport Layer (SSH-TRANS):** * **Role:** Handles initial connection, server authentication, and session security.
    - **Components:** Negotiation of encryption ciphers (AES, ChaCha20), key exchange (Diffie-Hellman), and **MAC (Message Authentication Code)** algorithms to ensure data integrity.
    - **Perfect Forward Secrecy (PFS):** Ensures that if a server's long-term host key is compromised in the future, past session data remains encrypted.

- **User Authentication Layer (SSH-USERAUTH):**
    - **Role:** Authenticates the client to the server.
    - **Components:** Processes the methods we discussed earlier (Public Key, Password, Keyboard-interactive). It runs "on top" of the secure transport layer.

- **Connection Layer (SSH-CONNECT):**
    - **Role:** The "multiplexer." It allows a single encrypted connection to be split into multiple logical **Channels**.
    - **Components:** Individual channels for interactive shells, `exec` commands, SFTP transfers, and port forwarding.

## Subsystems
SSH isn't just for a terminal; it acts as a wrapper for other "subsystems" that provide specific features.

| **Subsystem**      | **Technical Description**                                                                                                           | **Common Tool**     |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| **SFTP**           | **SSH File Transfer Protocol**. A full-featured file manipulation protocol (list, delete, resume) that runs over an SSH channel.    | `sftp` or FileZilla |
| **SCP**            | **Secure Copy Protocol**. A lightweight, non-interactive method for pushing/pulling files.                                          | `scp`               |
| **X11 Forwarding** | Encapsulates graphical window data (X Window System) so you can run GUI apps on a remote server and see them on your local desktop. | `ssh -X`            |

