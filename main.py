import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define known packer signatures (can be extended)
PACKER_SIGNATURES = {
    "UPX": b"UPX",
    "PECompact": b"PECompact",
    "ASPack": b"ASPack",
    "FSG": b"FSG",
    "UPolyX": b"UPolyX",
    "MEW": b"MEW"  #Minimal Executable Writer
}


def setup_argparse():
    """
    Sets up the argument parser for the command line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Detects executable packers in files.")
    parser.add_argument("file_path", help="Path to the file to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser


NOT_EXECUTABLE = "__not_executable__"


def detect_packer(file_path):
    """
    Detects if a file is packed and identifies the packer used.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        str: The name of the packer if detected, NOT_EXECUTABLE if the
            file has no MZ or ELF header, otherwise None for an
            executable with no known signature.

    Raises:
        ValueError: If the file is empty.
        OSError: If the file cannot be read.
    """
    with open(file_path, "rb") as f:
        data = f.read()

    if not data:
        raise ValueError(f"File is empty: {file_path}")

    # The gate runs before any signature search. Only MZ and ELF files are
    # considered executables here, so a Mach-O binary or a script gets the
    # not executable answer even if a packer name sits inside it.
    if not (data.startswith(b"MZ") or data.startswith(b"\x7fELF")):
        return NOT_EXECUTABLE

    for packer, signature in PACKER_SIGNATURES.items():
        # The search is over the whole file, not the header or section table.
        # A packer name appearing in a string, a resource, or compressed data
        # counts as a hit, and dict order decides the winner when several
        # signatures are present: UPX is checked first, so it wins ties. The
        # three byte signatures are short enough that chance matches in large
        # files are a real possibility, which is why the external check below
        # exists as a second opinion, not as the primary.
        if signature in data:
            logging.info(f"Detected packer: {packer}")
            return packer

    # Attempt to use external tools (peid, etc.) as a fallback.  This requires them to be installed.
    # Example (using 'file' command):
    try:
        # The fallback runs only when no signature matched, and it reads the
        # file command's prose, lowercased, for two words. It can confirm UPX
        # or a generic packed verdict, nothing more specific than that.
        result = subprocess.run(['file', file_path], capture_output=True, text=True, check=True)
        output = result.stdout.lower()

        if "upx" in output:
            return "UPX (External Tool)"
        elif "packed" in output:
            return "Packed (External Tool - Generic)"

    except FileNotFoundError:
         logging.warning("External file command not found. Install it to improve packer detection.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running external tool: {e}")

    return None


def main():
    """
    Main function to execute the file packer detector.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    file_path = args.file_path

    # Input validation: Check if the file path is valid
    if not isinstance(file_path, str):
        logging.error("Invalid file path. Please provide a string.")
        sys.exit(1)
    
    file_path = Path(file_path)  # Convert to Path object for easier handling.

    if not file_path.exists():
        logging.error(f"File does not exist: {file_path}")
        sys.exit(1)
    
    if not file_path.is_file():
        logging.error(f"Path is not a file: {file_path}")
        sys.exit(1)
        
    try:
        packer = detect_packer(str(file_path)) #Convert back to string for detect_packer function
    except ValueError as e:
        logging.error(str(e))
        sys.exit(1)
    except OSError as e:
        logging.error(f"Error reading file: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

    # Every detection outcome exits 0, including packed. Only validation
    # failures and read errors exit 1. A script wrapping this tool has to
    # parse the printed line to learn the verdict.
    if packer == NOT_EXECUTABLE:
        print("Packer detection does not apply: file is not a recognized executable (no MZ or ELF header).")
    elif packer:
        print(f"File is packed with: {packer}")
    else:
        print("File is not packed (or packer is not recognized).")


if __name__ == "__main__":
    main()

# Usage Examples:

# 1. Basic usage:
# python file_executable_packer_detector.py /path/to/your/executable.exe

# 2. Verbose mode:
# python file_executable_packer_detector.py -v /path/to/your/executable.exe

# 3.  Handling a file that doesn't exist:
# python file_executable_packer_detector.py /path/to/nonexistent_file.exe

# 4. Handling a directory:
# python file_executable_packer_detector.py /path/to/a/directory/

# Offensive Tool Integration (Illustrative Example - requires appropriate permissions & ethics):
# The tool can be integrated with offensive tools as a pre-analysis step.  For instance, before attempting to disassemble or decompile an executable,
# packer detection can guide the choice of unpacking strategies.

# Example (Conceptual):
# 1.  Run packer detection.
# 2.  If a packer is detected (e.g., UPX), run UPX to decompress the executable if UPX is available on system and user authorizes such actions.
# 3.  Proceed with analysis of the unpacked executable.
#
# Note: Actual unpacking involves execution of tools (UPX, etc.), requires caution, and must adhere to ethical guidelines and legal restrictions.