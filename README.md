# Traffic Mirror Packet Capture Decryptor
:warning: Not an official Palo Alto Networks program :warning: 

## Overview

This Python script is designed to decrypt encrypted network capture files (`.pcap.enc` or `.pcapng.enc`) packaged within ZIP archives. It handles batch processing of directories containing multiple ZIP files or a single ZIP file. The script expects AES-GCM encryption for the capture files, with the necessary decryption key, nonce, and authentication tag provided in an accompanying JSON file.

## Features

* **Flexible Input**: Accepts either a path to a single ZIP file or a path to a directory containing multiple ZIP files.
* **Broad Capture Format Support**: Decrypts both `.pcap.enc` and `.pcapng.enc` files.
* **AES-GCM Decryption**: Specifically designed for capture files encrypted using AES-GCM, ensuring both confidentiality and integrity via an authentication tag.
* **Key Material Handling**:
    * Expects a JSON file (e.g., `BASENAME.pcap.json` or `BASENAME.pcapng.json`) for each encrypted capture file, containing the Base64 encoded `key`, `nonce`, and `tag`.
    * The JSON key material file can be plaintext.

* **Private Key Support**:
    * Loads PEM-encoded private keys.
    * Detects and logs whether the provided private key is RSA or Elliptic Curve (EC).

* **Multiple Sets per ZIP**: Can process multiple encrypted capture file sets (e.g., `file1.pcap.enc` + `file1.pcap.json`, `file2.pcap.enc` + `file2.pcap.json`) within a single ZIP archive.
* **`info.txt` Handling**: If an `info.txt` file is present in the ZIP archive, it's extracted and copied for each successfully decrypted capture set, renamed to `BASENAME.pcap.info.txt` or `BASENAME.pcapng.info.txt`. Existing target info files will be overwritten.
* **Customizable Output**: Allows specifying a custom output directory for all decrypted files and accompanying `.info.txt` files. Defaults to the location of the source ZIP file(s).
* **Batch Mode Error Handling**: For directory processing, offers interactive prompting (`prompt`), automatic skipping (`skip_problematic`), or aborting all (`abort_all_on_problem`) when required files for a decryption set are missing. This can also be set via a command-line argument for non-interactive runs.
* **Graceful Exit**: Handles `Ctrl+C` (KeyboardInterrupt) for a cleaner shutdown.
* **Logging**: Provides informative console output, with an optional `--debug` flag for verbose logging.

## Prerequisites

* Python 3.12 or newer
* The `cryptography` Python library.

## Installation

1. Ensure you have Python 3.12+ installed.
2. ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

The script is run from the command line.

```bash
python3 traffic-mirror-pcap-decrypt.py <private_key_path> <input_path> [options]
```

## Command-Line Arguments
|Argument|Description|Required|
|--------|-----------|--------|
|`private_key_path`|Path to your PEM-encoded private key file (RSA or EC). An RSA key is needed if the .json key material files within the ZIP are RSA-encrypted.|Yes|
|`input_path`|Path to a single ZIP file or a directory containing multiple ZIP files to process.|Yes|
|`-o`, `--output-dir`|Optional. Directory to store decrypted files and accompanying .info.txt files. If not provided, outputs are saved in the same location as their source ZIP file. The directory is created if it doesn't exist.|No|
|`--on-missing-files`|Optional. Batch mode behavior when required files for a decryption set (e.g., .json key material) are missing. Choices: prompt, skip_problematic, abort_all_on_problem. Default: prompt.|No|
|`--debug`|Optional. Enable debug logging for more verbose output.|No|

# Examples
### Decrypt a single ZIP file, output to the same directory:

```bash
$ python3 traffic-mirror-pcap-decrypt.py key.pem ../us-east4-ep-tm-group1-s0wc/us-east4-ep-tm-group1-s0wc-20250604_053500_101524.zip
2025-06-04 15:50:00 - INFO - Script starting...
2025-06-04 15:50:00 - INFO - Processing ZIP: 'us-east4-ep-tm-group1-s0wc-20250604_053500_101524.zip'
2025-06-04 15:50:00 - INFO - Processing set: ENC='20250604_053500_101524.pcapng.enc', KEY_MATERIAL='20250604_053500_101524.pcapng.json'
2025-06-04 15:50:00 - INFO - Successfully decrypted '20250604_053500_101524.pcapng.enc'.
2025-06-04 15:50:00 - INFO - Decrypted output written to '../us-east4-ep-tm-group1-s0wc/20250604_053500_101524.pcapng'.
2025-06-04 15:50:00 - INFO - Finished ZIP 'us-east4-ep-tm-group1-s0wc-20250604_053500_101524.zip'. Successfully processed 1 set(s).
2025-06-04 15:50:00 - INFO - Script processing finished.
```

### Decrypt all ZIP files in a directory, output to a specific directory:

```bash
$ python3 traffic-mirror-pcap-decrypt.py key.pem ../us-east4-ep-tm-group1-s0wc --output-dir tmp
2025-06-04 15:52:51 - INFO - Script starting...
2025-06-04 15:52:51 - INFO - Output directory set to: tmp
2025-06-04 15:52:51 - INFO - Scanning directory: '../us-east4-ep-tm-group1-s0wc'
2025-06-04 15:52:51 - INFO - Found 548 ZIP file(s) for potential processing.
2025-06-04 15:52:51 - INFO - --- Processing ZIP 1/548: 'us-east4-ep-tm-group1-s0wc-20250130_074842_953309.zip' ---
2025-06-04 15:52:51 - INFO - Processing ZIP: 'us-east4-ep-tm-group1-s0wc-20250130_074842_953309.zip'
2025-06-04 15:52:51 - INFO - Processing set: ENC='20250130_074842_953309.pcap.enc', KEY_MATERIAL='20250130_074842_953309.pcap.json'
2025-06-04 15:52:51 - INFO - Successfully decrypted '20250130_074842_953309.pcap.enc'.
2025-06-04 15:52:51 - INFO - Decrypted output written to 'tmp/20250130_074842_953309.pcap'.
2025-06-04 15:52:51 - WARNING - Overwriting existing info file: 'tmp/20250130_074842_953309.pcap.info.txt'.
2025-06-04 15:52:51 - INFO - Finished ZIP 'us-east4-ep-tm-group1-s0wc-20250130_074842_953309.zip'. Successfully processed 1 set(s).
2025-06-04 15:52:51 - INFO - --- Processing ZIP 2/548: 'us-east4-ep-tm-group1-s0wc-20250602_183956_546704.zip' ---
2025-06-04 15:52:51 - INFO - Processing ZIP: 'us-east4-ep-tm-group1-s0wc-20250602_183956_546704.zip'
2025-06-04 15:52:51 - INFO - Processing set: ENC='20250602_183956_546704.pcap.enc', KEY_MATERIAL='20250602_183956_546704.pcap.json'
2025-06-04 15:52:51 - INFO - Successfully decrypted '20250602_183956_546704.pcap.enc'.
2025-06-04 15:52:51 - INFO - Decrypted output written to 'tmp/20250602_183956_546704.pcap'.
2025-06-04 15:52:51 - WARNING - Overwriting existing info file: 'tmp/20250602_183956_546704.pcap.info.txt'.
2025-06-04 15:52:51 - INFO - Finished ZIP 'us-east4-ep-tm-group1-s0wc-20250602_183956_546704.zip'. Successfully processed 1 set(s).
...
2025-06-04 15:52:03 - INFO - --- Processing ZIP 547/548: 'us-east4-ep-tm-group1-s0wc-20250604_160500_297016.zip' ---
2025-06-04 15:52:03 - INFO - Processing ZIP: 'us-east4-ep-tm-group1-s0wc-20250604_160500_297016.zip'
2025-06-04 15:52:03 - INFO - Processing set: ENC='20250604_160500_297016.pcapng.enc', KEY_MATERIAL='20250604_160500_297016.pcapng.json'
2025-06-04 15:52:03 - INFO - Successfully decrypted '20250604_160500_297016.pcapng.enc'.
2025-06-04 15:52:03 - INFO - Decrypted output written to 'tmp/20250604_160500_297016.pcapng'.
2025-06-04 15:52:03 - INFO - Finished ZIP 'us-east4-ep-tm-group1-s0wc-20250604_160500_297016.zip'. Successfully processed 1 set(s).
2025-06-04 15:52:03 - INFO - --- Processing ZIP 548/548: 'us-east4-ep-tm-group1-s0wc-20250604_161000_391558.zip' ---
2025-06-04 15:52:03 - INFO - Processing ZIP: 'us-east4-ep-tm-group1-s0wc-20250604_161000_391558.zip'
2025-06-04 15:52:03 - INFO - Processing set: ENC='20250604_161000_391558.pcap.enc', KEY_MATERIAL='20250604_161000_391558.pcap.json'
2025-06-04 15:52:03 - INFO - Successfully decrypted '20250604_161000_391558.pcap.enc'.
2025-06-04 15:52:03 - INFO - Decrypted output written to 'tmp/20250604_161000_391558.pcap'.
2025-06-04 15:52:03 - INFO - Finished ZIP 'us-east4-ep-tm-group1-s0wc-20250604_161000_391558.zip'. Successfully processed 1 set(s).
2025-06-04 15:52:03 - INFO - Finished processing directory '../us-east4-ep-tm-group1-s0wc'.
2025-06-04 15:52:03 - INFO - Script processing finished.
```

### Decrypt a directory of ZIPs, always skip sets with missing JSON files, with debug logging:
```bash
$ python3 traffic-mirror-pcap-decrypt.py pey.pem ../us-east4-ep-tm-group1-s0wc --on-missing-files skip_problematic --debug -o tmp
```

# Input Requirements
## Private Key (`private_key_path`)
* A PEM-encoded private key file.
* The script can load RSA or Elliptic Curve (EC) keys.

## Input Path (`input_path`)
* Can be a path to a single `.zip` file.
* Can be a path to a directory. The script will scan this directory (non-recursively) for `.zip` files to process.

## ZIP File Contents
Each ZIP file is expected to contain one or more sets of files for decryption. A "set" typically consists of:

1. Encrypted Capture File:

Named like `BASENAME.pcap.enc` or `BASENAME.pcapng.enc`.
This file contains the AES-GCM encrypted network capture data.

2. Key Material JSON File:

Named to correspond with the encrypted file: `BASENAME.pcap.json` or `BASENAME.pcapng.json`.
This file must be a JSON object containing the following keys:
* `"key"`: The AES encryption key, Base64 encoded.
* `"nonce"`: The nonce (Initialization Vector for GCM), Base64 encoded.
* `"tag"`: The GCM authentication tag, Base64 encoded.
Example JSON content:
JSON
```json
{"key": "BASE64_ENCODED_AES_KEY_HERE", "nonce": "BASE64_ENCODED_NONCE_HERE","tag": "BASE64_ENCODED_TAG_HERE"}
```

3. info.txt File:

If a file named exactly `info.txt` exists at the root of the ZIP archive, it will be processed.

## Output
* Decrypted Capture Files: For each successfully processed encrypted file (e.g., `BASENAME.pcap.enc`), a decrypted file will be generated (e.g., `BASENAME.pcap`). The same applies to `.pcapng.enc` files (resulting in `BASENAME.pcapng`).
* Info Files: If `info.txt` was present in the ZIP, it will be copied and renamed for each successfully decrypted set to `BASENAME.pcap.info.txt` or `BASENAME.pcapng.info.txt`. Existing files with this name in the output location will be overwritten.
* Output Location:
    * If `--output-dir` is specified, all output files are placed in that directory.
    * Otherwise, output files are placed in the same directory as the ZIP file from which they originated.

## Error Handling & Logging
* The script provides informative logs to the console. Use the `--debug` flag for more detailed output, which can be helpful for troubleshooting.
* If required files (like the `.json` key material file) are missing for a particular decryption set within a ZIP:
    * In single ZIP mode, processing for that set (and effectively the ZIP if it's the only set or errors occur early) will typically abort.
    * In directory (batch) mode, the behavior is controlled by the `--on-missing-files` argument (`prompt`, `skip_problematic`, `abort_all_on_problem`).
* Graceful `Ctrl+C` handling allows for user interruption without a full traceback.
* AES-GCM `InvalidTag` errors indicate that the decrypted data could not be authenticated, meaning it might be corrupt, tampered with, or the decryption key/nonce was incorrect.
