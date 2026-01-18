### **Part 1 - Deploy the Wazuh Virtual Machine**

To use Wazuh, you will set up a local server on your computer using a virtual machine. This does not require a company email or any paid service.

1. Download and install [**Oracle VirtualBox**](https://www.virtualbox.org/wiki/Downloads) to run the virtual machine.
    
2. Search online for **"Wazuh virtual machine OVA"** to find and download the pre-built Wazuh server file.
    
3. Open VirtualBox and go to **File > Import Appliance...**
    
4. Select the Wazuh .ova file you downloaded. Follow the prompts to import it.
    

![[_3e968639956d40b2840aab0888bc94f8_OracleVM-imported.png]]

### **Part 2 - Configure the Virtual Machine**

Before you start the VM, you must configure its memory to prevent errors.

1. In the main VirtualBox window, select your imported Wazuh VM.
    
2. Click the **Settings** button.
    
3. Go to the **System** tab. Adjust the **Base Memory** slider to **4096 MB (4 GB)**. This is a critical step to ensure your computer has enough resources to run both your operating system and the VM.
    
4. Click **OK** to save the setting.
    

![[_2226974daee247dba549e0234ebd4103_Wazuh-Base-Memory.png]]

### **Part 3 - Access the Wazuh Dashboard**

Now you will start the VM, configure a shared folder to get your data inside, and then access the dashboard from your browser.

1. **Start the VM:** Click the **Start** button in VirtualBox. Once it boots, you can press the **right Ctrl key** to get your mouse back from the VM's window.
    
2. **Set Up Shared Folder:** From the VirtualBox menu bar, go to **Devices > Shared Folders > Shared Folders Settings...**
    
    - Click the **Add new shared folder** icon (green plus sign).
        
    - For **Folder Path**, navigate to and select the [**tutorialdata**](https://drive.google.com/file/d/1nDz_DZB4ADbD4tvaDa54_l1FoT_jtVy4/view?usp=share_link) folder you **unzipped**.
        
    - For **Folder Name**, enter **buttercup-shared**. Ensure the **Auto-mount** box is checked and click **OK**.
        

![[_d37d55d80f744d2a8b9696972d3dc967_VM-Shared-Folder.png]]

3. **Fix Permissions:** After the VM boots, log in with **root / wazuh** (use these root credentials to access logs). Run the following commands to get the correct permissions for the shared folder:
```
usermod -aG vboxsf root
reboot
```

4. **Log in and Access:** After the VM reboots, log back in (with root credentials above). Run the command **ip a** to find your VM's IP address. The address will likely start with 192. Open a web browser on your computer and go to https://<your_VM_IP_address>. Allow and log in to the Wazuh dashboard with admin / admin.

### **Part 4 - Ingest and Analyze Data**

Now that your VM is running, you can get the data in for analysis.

1. **Access the Data:** In the VM's command line, run **cd /media/sf_buttercup-shared**. The sf_ prefix is added by VirtualBox to denote the shared folder.
    
2. **Create Ingestion File:** Run **nano ingest.yml** and copy/paste the following content. **Note:** This is a YAML file; be precise with your spacing.
```
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /media/sf_buttercup-shared/mailsv/*.log
    - /media/sf_buttercup-shared/vendor_sales/*.csv
    - /media/sf_buttercup-shared/www1/*.log
    - /media/sf_buttercup-shared/www2/*.log
    - /media/sf_buttercup-shared/www3/*.log
output.logstash:
  hosts: ["localhost:5044"]
```


![[_f5e44e3be33c4b99bb959a3f34e21b5e_Nano-File.png]]

Press **Ctrl+X**, then type **Y**, and press **Enter** to save.

3. **Run Ingestion:** Run **/usr/share/filebeat/bin/filebeat -c ingest.yml -e**. The command will process your logs and send them to the dashboard.

4. **Verify & Analyze:** After the command finishes, go to your browser. If you don't see logs immediately, wait a few minutes and refresh.

- Go back to the Dashboard and locate the **Discover** option under the **Explore** option.
    
- In the time range, choose **Absolute**, select a very old start date (e.g., January 1, 2000), and click **Update**.
    
- In the search bar, type * and press **Enter**. You are now ready to answer the questions in the activity. _**Note:**_ If you get less than 100 hits, you should revise the steps above.
    

You're done! Once your Wazuh environment is set up