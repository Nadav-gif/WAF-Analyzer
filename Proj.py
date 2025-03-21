import argparse
import subprocess
import sys
import os


def run_json_mode(api_key, file_path):
    """Runs the project in JSON mode"""
    os.environ["API_KEY"] = api_key  # Pass API key as an environment variable
    os.environ["FILE_PATH"] = file_path
    import JSON  # Import and execute JSON output script


def run_ui_mode(api_key, file_path):
    """Runs the project in UI mode"""
    os.environ["API_KEY"] = api_key  # Pass API key as an environment variable
    os.environ["FILE_PATH"] = file_path
    subprocess.run([sys.executable, "-m", "streamlit", "run", "UI.py"], check=True)  # Runs UI.py instead of proj.py


def main():
    """Main function to handle CLI arguments"""
    parser = argparse.ArgumentParser(description="Run the project in either JSON or UI mode.")
    parser.add_argument("--output", choices=["JSON", "UI"], required=True, help="Choose output mode: JSON or UI")
    parser.add_argument("--api_key", required=True, help="Provide the API key for authentication")
    parser.add_argument("--file_path", required=True, help="Path to the WAF log file")

    args = parser.parse_args()

    if args.output == "JSON":
        run_json_mode(args.api_key, args.file_path)
    elif args.output == "UI":
        run_ui_mode(args.api_key, args.file_path)


if __name__ == "__main__":
    main()
