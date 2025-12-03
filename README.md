# Experimental Digital Signature for Cities: Skylines II mods

## Dependencies

- Python 3.10.12

## Setup (Linux/MacOS)

1. Go to the project root folder
2. Create python virtual environment
   ```shell
   python3 -m venv .venv
   ```
3. Activate virtual environment
   ```shell
   source .venv/bin/activate
   ```
4. Install dependencies
   ```shell
   pip install -r requirements.txt
   ```

## How to run (Linux/MacOS)

1. Go to the project root folder
2. Activate virtual environment (if not already activated)
   ```shell
   source .venv/bin/activate
   ```
3. Run the program with the required arguments
   - Generate a new key pair
     ```shell
     python3 src/main.py generate-keys --output-private path/to/private_key.pem --output-public path/to/public_key.pem
     ```
   - Sign a mod file
     ```shell
     python3 src/main.py sign path/to/modfile.zip path/to/private_key.pem
     ```
   - Verify a mod file
     ```shell
     python3 src/main.py verify path/to/modfile.zip path/to/public_key.pem
     ```
