![Banner](banner.png)

# file-executable-packer-detector
Identifies whether a file is packed using common executable packers (UPX, PECompact, etc.) and reports the packer used. Helps detect attempts to hide malicious code within executables. - Focused on File operations and analysis

## Install
`git clone https://github.com/ShadowGuardAI/file-executable-packer-detector`

## Usage
`python3 main.py <file_path> [-v]`

Packer signatures are searched across the whole file, but only after the file is confirmed as a plausible executable by an MZ or ELF header. A file with no MZ or ELF header gets a plain line saying packer detection does not apply, exits 0, and is never reported as packed. An empty file and any read error are distinct error outcomes and exit 1, separate from the not packed result for a scanned executable with no known signature.

## Parameters
- `file_path`: Path to the file to analyze (required, positional)
- `-h`: Show help message and exit
- `-v`: Enable verbose output

## License
Copyright (c) ShadowGuardAI
