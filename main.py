import os
import re
import shutil
import argparse
import logging
import datetime
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define regular expressions for common credentials
CREDENTIAL_REGEXES = [
    re.compile(r"(?i)api_key\s*=\s*['\"]?([a-zA-Z0-9_-]+)['\"]?"),
    re.compile(r"(?i)password\s*=\s*['\"]?([a-zA-Z0-9!@#$%^&*()_+=-]+)['\"]?"),
    re.compile(r"(?i)secret\s*=\s*['\"]?([a-zA-Z0-9_-]+)['\"]?"),
    re.compile(r"(?i)access_token\s*=\s*['\"]?([a-zA-Z0-9_-]+)['\"]?"),
    re.compile(r"(?i)bearer\s*([a-zA-Z0-9._-]+)") #added bearer token detection
    # Add more regex patterns as needed
]

# Define file types to sanitize
FILE_TYPES = {
    "bash": "~/.bash_history",
    "zsh": "~/.zsh_history",
    "powershell": "~/Documents/WindowsPowerShell/PSReadLine/ConsoleHost_history.txt",
    "jupyter": ".ipynb"  # Will search recursively for .ipynb files
}


def sanitize_file(filepath):
    """
    Sanitizes a file by removing credentials matching the defined regular expressions.

    Args:
        filepath (str): The path to the file to sanitize.

    Returns:
        bool: True if the file was successfully sanitized, False otherwise.
    """
    try:
        # Create a backup of the original file
        backup_filepath = filepath + "." + datetime.datetime.now().strftime("%Y%m%d%H%M%S") + ".bak"
        shutil.copy2(filepath, backup_filepath)  # copy2 preserves metadata
        logging.info(f"Backed up original file to: {backup_filepath}")

        # Read the file content
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Sanitize the content by replacing credentials with placeholders
        sanitized_content = content
        for regex in CREDENTIAL_REGEXES:
            sanitized_content = regex.sub(r"\g<0>REDACTED", sanitized_content)  # Replace with "REDACTED"
            
        # Write the sanitized content back to the file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(sanitized_content)

        logging.info(f"Successfully sanitized file: {filepath}")
        return True

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return False
    except Exception as e:
        logging.error(f"An error occurred while sanitizing file {filepath}: {e}")
        return False


def sanitize_jupyter_notebook(filepath):
    """
    Sanitizes a Jupyter Notebook file by removing credentials from code cells.

    Args:
        filepath (str): The path to the Jupyter Notebook file.

    Returns:
        bool: True if the file was successfully sanitized, False otherwise.
    """
    try:
        import json  # Import here to avoid dependency if not using Jupyter functionality

        # Create a backup of the original file
        backup_filepath = filepath + "." + datetime.datetime.now().strftime("%Y%m%d%H%M%S") + ".bak"
        shutil.copy2(filepath, backup_filepath)
        logging.info(f"Backed up original file to: {backup_filepath}")

        # Read the JSON content of the Jupyter Notebook
        with open(filepath, "r", encoding="utf-8") as f:
            notebook_data = json.load(f)

        # Iterate through the cells and sanitize code cells
        for cell in notebook_data["cells"]:
            if cell["cell_type"] == "code":
                source = cell["source"]
                if isinstance(source, list): # handling different jupyter notebook formats
                    source_str = "".join(source) #join list of strings into one string
                    sanitized_source = source_str
                    for regex in CREDENTIAL_REGEXES:
                        sanitized_source = regex.sub(r"\g<0>REDACTED", sanitized_source)
                    cell["source"] = sanitized_source.splitlines(keepends=True) #convert back to list of strings
                elif isinstance(source, str): #handling different jupyter notebook formats
                    sanitized_source = source
                    for regex in CREDENTIAL_REGEXES:
                        sanitized_source = regex.sub(r"\g<0>REDACTED", sanitized_source)
                    cell["source"] = sanitized_source
                else:
                    logging.warning(f"Unexpected format for cell source: {type(source)}")


        # Write the sanitized content back to the file
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(notebook_data, f, indent=1)  # indent for readability

        logging.info(f"Successfully sanitized Jupyter Notebook: {filepath}")
        return True

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return False
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in {filepath}: {e}")
        return False
    except ImportError:
        logging.error("The 'json' module is required to sanitize Jupyter Notebooks.  Please install it (e.g., 'pip install json').")
        return False
    except Exception as e:
        logging.error(f"An error occurred while sanitizing Jupyter Notebook {filepath}: {e}")
        return False


def find_and_sanitize_jupyter_notebooks(directory):
    """
    Recursively finds and sanitizes Jupyter Notebook files within a directory.

    Args:
        directory (str): The directory to search in.
    """
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".ipynb"):
                filepath = os.path.join(root, file)
                sanitize_jupyter_notebook(filepath)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="cma-Credential-Sanitizer: Removes secrets from command history files and Jupyter Notebooks.")
    parser.add_argument(
        "--filetype",
        "-t",
        choices=FILE_TYPES.keys(),
        help="The type of file to sanitize (bash, zsh, powershell, jupyter).",
    )
    parser.add_argument(
        "--filepath",
        "-f",
        help="The specific file path to sanitize.  Overrides --filetype if provided.",
    )
    parser.add_argument(
        "--directory",
        "-d",
        help="The directory to recursively search for Jupyter Notebooks (.ipynb files).  Only applies when --filetype is jupyter.",
    )
    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Sanitize all supported file types (bash, zsh, powershell, Jupyter). Jupyter Notebooks will be searched recursively in the current directory.",
    )
    parser.add_argument(
        "--regex_file",
        "-r",
        help="Path to a file containing custom regular expressions (one per line).",
    )

    return parser


def main():
    """
    The main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    global CREDENTIAL_REGEXES

    # Load custom regexes from file if provided
    if args.regex_file:
        try:
            with open(args.regex_file, "r") as f:
                custom_regexes = [re.compile(line.strip()) for line in f if line.strip()]
                CREDENTIAL_REGEXES.extend(custom_regexes)
            logging.info(f"Loaded {len(custom_regexes)} custom regexes from {args.regex_file}")
        except FileNotFoundError:
            logging.error(f"Regex file not found: {args.regex_file}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading regex file {args.regex_file}: {e}")
            sys.exit(1)

    # Input validation:  Make sure at least one action is specified
    if not any([args.filetype, args.filepath, args.directory, args.all]):
        parser.print_help()
        sys.exit(1)
    
    if args.filepath:
        # Specific file path provided
        if sanitize_file(args.filepath):
            logging.info("Sanitization complete.")
        else:
            logging.error("Sanitization failed.")
        sys.exit(0)  # Exit after processing the specified file

    if args.filetype == "jupyter" and args.directory:
      find_and_sanitize_jupyter_notebooks(args.directory)
      sys.exit(0)


    if args.filetype:
        # Sanitize based on file type
        if args.filetype == "jupyter":
            if args.directory:
                find_and_sanitize_jupyter_notebooks(args.directory)
            else:
                find_and_sanitize_jupyter_notebooks(os.getcwd()) # Default to current directory
        else:
            filepath = os.path.expanduser(FILE_TYPES[args.filetype])
            if sanitize_file(filepath):
                logging.info("Sanitization complete.")
            else:
                logging.error("Sanitization failed.")
    elif args.all:
        # Sanitize all supported file types
        for filetype, filepath in FILE_TYPES.items():
            if filetype == "jupyter":
                find_and_sanitize_jupyter_notebooks(os.getcwd()) # Default to current directory for Jupyter
            else:
                filepath = os.path.expanduser(filepath)
                sanitize_file(filepath)
        logging.info("Sanitization complete for all supported file types.")

    # Example usages (these won't actually execute in the script, but serve as documentation)
    """
    Example Usages:

    1. Sanitize bash history:
       python cma-Credential-Sanitizer.py -t bash

    2. Sanitize a specific file:
       python cma-Credential-Sanitizer.py -f /path/to/my/file.txt

    3. Sanitize all supported file types:
       python cma-Credential-Sanitizer.py -a

    4. Recursively sanitize Jupyter Notebooks in a directory:
       python cma-Credential-Sanitizer.py -t jupyter -d /path/to/notebooks

    5. Use a custom regex file:
       python cma-Credential-Sanitizer.py -t bash -r custom_regexes.txt

    custom_regexes.txt (example):
    (?i)database_password\s*=\s*['\"]?([a-zA-Z0-9!@#$%^&*()_+=-]+)['\"]?
    """


if __name__ == "__main__":
    main()