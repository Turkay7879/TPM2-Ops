# TPM2-Ops

This command line utility facilitates operations related to TPM2 (Trusted Platform Module 2) on both Windows and Linux systems. It provides functionalities to read the hash of a public key generated by TPM2 and create signatures of messages for later verification.

## Features

- **Read Hash**: Extract and display the hash of a TPM2-generated public key.
- **Create Signature**: Generate a signature for a specific message using TPM2 which can be used for later verification.

## Prerequisites

### For Windows
- Ensure TPM2-compliant hardware is present and activated in the BIOS settings.

### For Linux
- The following packages must be installed:
  - `tpm2-abrmd`
  - `libtss2-tcti-tabrmd-dev`
- Run the tool with root privileges. Use `sudo` to run commands as the superuser.

## Installation

### Windows

1. Download the latest release from the [Releases](https://github.com/Turkay7879/TPM2-Ops/releases) page.
2. Run the tool on Windows Terminal/CMD/PowerShell similar to Linux.

### Linux

1. Make sure to install the required packages if they are not installed:
   ```bash
   sudo apt-get update
   sudo apt-get install tpm2-abrmd libtss2-tcti-tabrmd-dev
2. Run the tool as following (Message and key auth are only required for SIGN):
   ```bash
   sudo ./TPM2-Ops [CREATE|SIGN] YOUR_MESSAGE KEY_AUTH
