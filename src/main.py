import argparse
import sys
import os
import sign_service

def generate_keys_handler(output_private: str, output_public: str):
    sign_service.generate_keys(output_private, output_public)
    
    print("[SUCCESS] Keys generated successfully:")
    print(f"  - Private key: {output_private}")
    print(f"  - Public key: {output_public}")

def sign_handler(zip_path: str, private_key_path: str):
    if not os.path.exists(zip_path):
        print(f"[ERROR] ZIP file not found: {zip_path}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(private_key_path):
        print(f"[ERROR] Private key file not found: {private_key_path}", file=sys.stderr)
        sys.exit(1)
    
    try:
        sign_service.sign(zip_path, private_key_path)
        print(f"[SUCCESS] Signed ZIP file: {zip_path}")
    except Exception as e:
        print(f"[ERROR] Failed to sign: {e}", file=sys.stderr)
        sys.exit(1)

def verify_handler(zip_path: str, public_key_path: str):
    if not os.path.exists(zip_path):
        print(f"[ERROR] ZIP file not found: {zip_path}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(public_key_path):
        print(f"[ERROR] Public key file not found: {public_key_path}", file=sys.stderr)
        sys.exit(1)
    
    try:
        is_valid = sign_service.verify(zip_path, public_key_path)
        print(f"Verification result: {'Valid' if is_valid else 'Invalid'}")
        sys.exit(0 if is_valid else 1)
    except Exception as e:
        print(f"[ERROR] Verification failed: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Digital Signature Tool for Cities: Skylines II Mods"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Generate keys command
    gen_parser = subparsers.add_parser("generate-keys", help="Generate RSA key pair")
    gen_parser.add_argument("--output-private", required=True, help="Path for private key output")
    gen_parser.add_argument("--output-public", required=True, help="Path for public key output")
    
    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign a ZIP file")
    sign_parser.add_argument("zip_path", help="Path to ZIP file to sign")
    sign_parser.add_argument("private_key_path", help="Path to private key")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a signed ZIP file")
    verify_parser.add_argument("zip_path", help="Path to signed ZIP file")
    verify_parser.add_argument("public_key_path", help="Path to public key")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == "generate-keys":
        generate_keys_handler(args.output_private, args.output_public)
    elif args.command == "sign":
        sign_handler(args.zip_path, args.private_key_path)
    elif args.command == "verify":
        verify_handler(args.zip_path, args.public_key_path)

if __name__ == "__main__":
    main()
