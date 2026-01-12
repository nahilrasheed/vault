Signing kernel modules with a machine-owner key (MOK) that you generate and enroll in your system's firmware.
- To run VMware Workstation on Fedora with Secure Boot enabled, you must sign the `vmmon` and `vmnet`

### **Phase 1: Generate a Key Pair**
You only need to do this once. This creates a trusted "identity" for you to sign drivers with.

1. **Create a directory for your keys (for safekeeping):**
    ```bash
    sudo mkdir -p /root/module-signing
    cd /root/module-signing
    ```
2. Generate the public and private keys:
    Run this command exactly. It creates a certificate valid for 10 years.
    ```bash
    sudo openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=VMware/"
    ```
    - `MOK.priv`: Private key (Keep safe! Used to sign modules).
    - `MOK.der`: Public key (This gets enrolled in your BIOS/EFI).

### **Phase 2: Enroll the Key in Firmware**
You must tell your computer's firmware (BIOS/UEFI) to trust this new key.
1. **Import the public key:**
    ```
    sudo mokutil --import MOK.der
    ```
    - It will ask you to create a **one-time password**. Remember this password; you will need it in the next step.
2. **Reboot your computer:**
    ```
    sudo reboot
    ```
3. Perform the Enrollment (The "Blue Screen"):
    During boot, before Fedora loads, you will see a blue screen labeled Shim UEFI key management.
    - Press any key to interrupt the boot.
    - Select **Enroll MOK**.
    - Select **Continue**.
    - Select **Yes**.
    - **Enter the password** you created in Step 1.
    - Select **Reboot**.

### **Phase 3: Sign the Modules**
Now that your system trusts the key, you must sign the specific VMware modules. **You will need to repeat this phase every time you update your Linux kernel or VMware version.**
1. Locate the sign-file utility:
    Fedora puts this in the kernel headers.
```
# Define the signer path variable for easier use
SIGNER="/usr/src/kernels/$(uname -r)/scripts/sign-file"
```
1. Locate your VMware modules:
    They are usually in /lib/modules/$(uname -r)/misc/.
    (Note: If the files end in .ko.xz, you must decompress them using xz -d before signing, then recompress them. However, manually compiled VMware modules are usually just .ko).
2. **Run the signing commands:**
```
# Sign vmmon
sudo $SIGNER sha256 /root/module-signing/MOK.priv /root/module-signing/MOK.der $(modinfo -n vmmon)

# Sign vmnet
sudo $SIGNER sha256 /root/module-signing/MOK.priv /root/module-signing/MOK.der $(modinfo -n vmnet)
```
### **Phase 4: Load and Verify**
1. **Load the signed modules:**
```
sudo modprobe vmmon
sudo modprobe vmnet
```
1. **Verify they are loaded:**
```
lsmod | grep vm
```
    _If you see `vmmon` and `vmnet` in the output, you are successful._
2. **Restart VMware Service:**
```
sudo systemctl restart vmware.service
```

### **Troubleshooting**
- **"Key rejected by service":** This means the enrollment in Phase 2 didn't happen correctly. Run `mokutil --test MOK.der` to see if the key is enrolled. If it says "not enrolled," try Phase 2 again.
- **"File not found":** Ensure you have `kernel-devel` installed (`sudo dnf install kernel-devel`). The `sign-file` tool is part of that package.

