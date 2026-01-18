## WPA/WPA2 Cracking

As mentioned above, WPA/WPA2 cracking begins by listening to Wi-Fi traffic to capture the 4-way handshake between a device and the access point. Since waiting for a device to connect or reconnect can take some time, deauthentication packets are sent to disconnect a client, forcing it to reconnect and initiate a new handshake, which is captured. After the handshake is captured, the attacker can crack the password (**PSK**) by using brute-force or dictionary attacks on the captured handshake file.

The WPA password cracking process involves capturing a Wi-Fi network's handshake to attempt a PSK (password) decryption. First, an attacker places their wireless adapter into monitor mode to scan for networks, then targets a specific network to capture the 4-way handshake. Once the handshake is captured, the attacker runs a brute-force or dictionary attack using a tool like aircrack-ng to attempt to match a wordlist against the passphrase.

The WPA 4-way handshake is a process that helps a client device (like your phone or laptop) and a Wi-Fi router confirm they both have the right "password" or Pre-Shared Key (PSK) before securely connecting. Here's a simplified rundown of what happens:

- **Router sends a challenge:** The router (or access point) sends a challenge" to the client, asking it to prove it knows the network's password without directly sharing it.
- **Client responds with encrypted information:** The client takes this challenge and uses the PSK to create an encrypted response that only the router can verify if it also has the correct PSK.
- **Router verifies and sends confirmation:** If the router sees the client’s response matches what it expects, it knows the client has the right PSK. The router then sends its own confirmation back to the client.
- **Final check and connection established:** The client verifies the router's response, and if everything matches, they finish setting up the secure connection.

This handshake doesn't directly reveal the PSK itself but involves encrypted exchanges that depend on the PSK.
