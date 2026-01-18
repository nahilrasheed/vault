Regshot is a widely used utility, especially when analysing malware on Windows. It works by creating two "snapshots" of the registry—one before the malware is run and another afterwards. The results are then compared to identify any changes.

Malware aims to establish persistence, meaning it seeks to run as soon as the device is switched on. A common technique for malware is to add a `Run` key into the registry, which is frequently used to specify which applications are automatically executed when the device is powered on.

1. Let's load up Regshot and create a capture of the registry as it currently exists.
2. First, change the output directory of the capture to the user's Desktop using the box with three dots in the "Output path" section.
3. Then, once set, let's create our first snapshot. Press **1st shot** and then **Shot** on the dropdown. Please note that this may take a few minutes to complete.
4. Now that we have taken a snapshot of the registry, you should proceed with **executing the malware sample** and take another snapshot. We will then compare the difference.
5. Once we have executed our sample, let's return to Regshot and capture our second snapshot, using the same procedure as above. Click on the **2nd shot** button and press **Shot** in the dropdown. Regshot is now capturing the registry again, and outputting the differences to a file.
6. And now, after a few seconds, let's press the **Compare** button that appears.
7. We can search for the executable within the log that opens up.

