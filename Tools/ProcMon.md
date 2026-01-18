ProcMon (Process Monitor) from the Sysinternals suite is used to monitor and investigate how processes are interacting with the Windows operating system. It is a powerful tool that allows us to see exactly what a process is doing. For example, reading and writing registry keys, searching for files, or creating network connections.

1. Open Process Monitor (ProcMon)
2. Process Monitor will automatically start capturing events of various processes on the system.
3. Run the sample
4. To stop capturing more events, click on the **Play** button in the toolbar of Process Monitor.
5. To apply some filters, click on the **Filter** button, and then **Filter** within the dropdown.
6. we can apply a filter like
	1. Apply the **Process Name** filter
	2. Set the condition to **is**
	3. Put in the name of the process we wish to see within the text area
	4. Press the **Add** button to apply this filter
	5. And finally click **OK** to save.
7. Now it is much easier to investigate how the process is interacting with the operating system. Here are some **Operations** that may be of interest to us:
	- RegOpenKey
	- CreateFile
	- TCP Connect
	- TCP Recieve
8. You can remove the filters you've previously applied by pressing the filter in the **Filter** list, and pressing **Remove**
8. You can also reset the filters using the **Reset Filter** option when clicking on the **Filter** heading.