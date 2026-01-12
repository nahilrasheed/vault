PeStudio is **a tool to find suspicious artifacts within executable files to accelerate the first malware assessment**. Using this tool, the analyst can easily spot the functionalities commonly used for malicious activities by malware creators.
- https://www.winitor.com/


- First, we will launch PeStudio and load the executable into it.
-  You can drag and drop the executable into the PeStudio window, or load it by selecting `File -> Open File` from the toolbar. PeStudio will display some information about the executable.
- the `**file > sha256**` property within the table is of interest. This value is a checksum, which is a unique identifier for the executable. We can keep a note of this SHA256 as threat intelligence.
- reviewing the "Strings" of the executable. You can do this by clicking on the "strings" indicator on the left pane of PeStudio.
- 