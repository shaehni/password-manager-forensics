# KeePass Search Pattern Definition
This document defines the forensically relevant artefacts, and their structure, that can be found in KeePass files and in a memory dump.

## database.kdbx
A KeePass database file contains all vault data. This file usually has the file ending `.kdbx` and the following file header: `03 D9 A2 9A 67 FB 4B B5`

### Relevant Artefacts
- Header bytes 8-9: File format version of the database (minor)
- Header bytes 10-11: File format version of the database (major)
- The rest of the header contains variable-length meta data in the form: `Type` (1 byte), `Length` (2 bytes), `Data` (according to length). The following types are of forensic relevance:
  - `03`: Compression flag (gzip)
  - `04`: Master seed
  - `05`: Transform seed
  - `06`: Transform rounds
  - `07`: Initialisation vector
  - `00`: End of header
- Rest of file: Payload area (encrypted vault)

### Availability
The database meta data is part of the KeePass database file. It is therefore always available in an intact file.

### Encrypted Vault Data
Vault data is stored as encrypted XML. Decryption is performed by first creating a composite key from the master password and/or key files. Then creating the master key through AES transformation and by using the master seed. A decryption context is then set up using the master key and the initialisation vector. The process is described in detail [here][1]. PMF uses the external [pykeepass][2] library to perform vault decryption.

[1]: https://gist.github.com/msmuenchen/9318327
[2]: https://github.com/libkeepass/pykeepass

***

## KeePass.config.xml
The KeePass config file contains settings about the KeePass application. It is saved in the application directory and has the file name `KeePass.config.xml`. As the file ending suggests, it is in XML format.

### Relevant Artefacts
- `<Configuration><Defaults><KeySources><Association>`: This element stores the path to the last opened database files (`<DatabasePath>`), whether a master password is set for the respective file (`<Password>`), and the corresponding key file, if applicable (`<KeyFilePath>`). The setting to store this information can be turned off by a user, but it is enabled by default.
- `<Configuration><Application><MostRecentlyUsed>`: This element stores the most recently used database files as `<Items><ConnectionInfo><Path>`.
- `<Configuration><PasswordGenerator>`: This element stores the last used settings of the password generator.

### Availability
The configuration file is stored in the application directory as cleartext XML.

***

## Memory
### Master Password
In the analysed memory dump, the master password appeard as part of the following pattern: `5E DF 27 D1 00 3B 00 94 [Master Password]`, followed with at least 10 `00` bytes, with a `00` padding between every character of the password. To reduce false positives, unlikely strings (<8 characters, non-printable characters) are filtered out from the results. However, as KeePass implements measures to avoid cleartext leaks of the master password in memory, this pattern matching method is not reliable.

### Vault Passwords
Vault credentials (passwords) are stored in memory in a data structure with the format `00 A0 57 ?? ?? ?? 7F 00 00 [XX] 00 00 00 00 00 00 00 [Password] 00 00` where `[XX]` indicates the lenght of the following string (possible password). Searching for this structure results in false positives. These are reduced by filtering out unlikely strings (<8 characters, non-printable characters, only numbers, or only capital letters).

