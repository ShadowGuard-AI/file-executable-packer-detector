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


def detect_packer(file_path):
    """
    Detects if a file is packed and identifies the packer used.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        str: The name of the packer if detected, otherwise None.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(4096)  # Read the first 4KB for signature detection

            for packer, signature in PACKER_SIGNATURES.items():
                if signature in header:
                    logging.info(f"Detected packer: {packer}")
                    return packer

        # Attempt to use external tools (peid, etc.) as a fallback.  This requires them to be installed.
        # Example (using 'file' command):
        try:
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

    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except PermissionError:
        logging.error(f"Permission denied to access file: {file_path}")
        return None
    except Exception as e:
        logging.error(f"An error occurred: {e}")
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
        if packer:
            print(f"File is packed with: {packer}")
        else:
            print("File is not packed (or packer is not recognized).")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


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