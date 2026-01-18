YARA is a tool used to identify and classify malware based on patterns in its code. By writing custom rules, analysts can define specific characteristics to look for—such as particular strings, file headers, or behaviours—and YARA will scan files or processes to find matches, making it invaluable for detecting malicious code.
### How They Work
- **Pattern Definition:** Analysts identify unique characteristics (strings, code) in a malware sample. 
- **Rule Creation:** These characteristics are encoded into a YARA rule file (`.yar`). 
- **Scanning:** The YARA tool scans files, memory, or data streams for these patterns. 
- **Matching:** If conditions are met, the rule triggers, flagging the file as malicious or matching a threat family.
### When it is used
- **Post-incident analysis**: when the security team needs to verify whether traces of malware found on one compromised host still exist elsewhere in the environment.
- **Threat Hunting**: searching through systems and endpoints for signs of known or related malware families.
- **Intelligence-based scans**: applying shared YARA rules from other defenders or kingdoms to detect new indicators of compromise.
- **Memory analysis**: examining active processes in a memory dump for malicious code fragments.
## YARA Rules
YARA rules are signature-based detection patterns, like a programming language, used in cybersecurity to identify and classify malware or malicious files by matching specific text strings, hex patterns, or code fragments within files or memory. They function as "fingerprints" for threats, allowing security analysts to detect known malware, find variants, hunt for threats, and perform forensic analysis by defining conditions (metadata, strings, logic) that trigger a match, making them essential for incident response.  

### Syntax
```
rule name{
meta:
strings:
condition:
}
```
- In the **strings** section, we have defined variables that include the value to look out for: $cmd
- In the **condition** section, we define when the rule will match the scanned file. In this case, if any of the specified strings are present.
### Rule Structure
- **Metadata (`meta`):** Non-functional descriptive information (author, date, description, hash). Used for organization and documentation.
- **Strings (`strings`):** The variables (identifiers) defining what to search for. The specific text, hex, or regex patterns to search for. 
- **Conditions (`condition`):** The Boolean logic that determines if a file/process matches the rule.
### String Types & Modifiers
Strings are prefixed with `$` and can be categorized into three types:
#### Text Strings
Plaintext sequences. Default behavior is ASCII and case-sensitive.
- **`nocase`:** Ignores capitalization.
- **`wide`:** Searches for 2-byte Unicode (UTF-16) characters. (Many Windows executables use two-byte Unicode characters.)
- **`ascii`:** Enforces 1-byte character searching (often used with `wide`).
- **`xor`:** Searches for the string encoded with all possible 1-byte XOR keys.
- **`base64` / `base64wide`:** Searches for the Base64 encoded version of the string.
#### Hexadecimal Strings
Used for raw byte sequences, shellcode, or non-printable signatures. Enclosed in curly braces `{ }`.
- **Wildcards:** `??` represents an unknown byte.
- **Jumps:** `[x-y]` defines a variable range of bytes between two static sequences.
#### Regular Expressions (Regex)
Flexible patterns for varying data like URLs or obfuscated commands. Enclosed in forward slashes `/ /`.
- _Note:_ Resource-intensive; excessive use can degrade scan performance.
### Conditions (Logic)
The condition determines the rule's verdict.
- **Boolean Operators:** `and`, `or`, `not`.
- **Quantifiers:** 
	- `any of them`: Triggers if any defined string is found.
    - `all of them`: Triggers only if every defined string is found.
    - `x of ($s*)`: Triggers if a specific count of a string set is found.
- **File Properties:**
    - `filesize`: Filter based on file size (e.g., `filesize < 10MB`).
    - `uint16(0) == 0x5A4D`: Checks for specific headers (e.g., MZ header at the start of a file).

Example:
```php
rule rule1
{
	meta:
        author = "TBFC SOC L2"
        description = "IcedID Rule"
        date = "2025-10-10"
        confidence = "low"
        
    strings:
        $flag_string = "MalString"
		$xmas = "Christmas" nocase
	    $xmaswide = "Christmas" wide ascii
	    $hidden = "Malhare" xor
	    $b64 = "SOC-mas" base64
        $mz = { 4D 5A 90 00 }   // MZ header of a Windows executable
        $hex_string = { E3 41 ?? C8 G? VB }
        $url = /http:\/\/.*malhare.*/ nocase
        $cmd = /powershell.*-enc\s+[A-Za-z0-9+/=]+/ nocase

    condition:
        $flag_string 
        // OR
        any of them
		// OR
	    all of them
		// OR
		($s1 or $s2) and not $benign
		// OR
		any of them and (filesize < 700KB)
}
```

## CLI Usage
Basic execution syntax: `yara [options] rule_file.yar target_directory_or_file`

|**Flag**|**Function**|
|---|---|
|**`-r`**|**Recursive:** Scans subdirectories.|
|**`-s`**|**Show Strings:** Displays the specific string matches that triggered the rule.|
|**`-m`**|**Metadata:** Displays metadata for matching rules.|
