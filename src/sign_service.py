import base64
import zipfile
from constants import SIG_FILENAME
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(output_private: str, output_public: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # save private key
    with open(output_private, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # save public key
    public_key = private_key.public_key()
    with open(output_public, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def hash_zip_content(zip_path):
    hasher = hashes.Hash(hashes.SHA256())
    
    with zipfile.ZipFile(zip_path, "r") as zin:
        # sort file names to ensure consistent hashing
        file_list = sorted(zin.namelist())
        
        for filename in file_list:
            # skip file signature to avoid looping hash
            if filename == SIG_FILENAME:
                continue
                
            # update hash with filename to prevent rename attack
            hasher.update(filename.encode("utf-8"))
            
            # update hash with file content
            with zin.open(filename) as f:
                hasher.update(f.read())
    
    return hasher.finalize()

def sign(zip_path, private_key_path):
    # load private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    
    # calculate hash of zip content
    content_hash = hash_zip_content(zip_path)

    # create digital signature
    signature = private_key.sign(
        content_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=0  # deterministic signature with no salt
        ),
        hashes.SHA256()
    )

    # TEST: corrupt signature by flipping one byte
    # signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])

    # encode signature to base64 for readable format
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    # add signature to zip content
    with zipfile.ZipFile(zip_path, "a") as zout:
        zout.writestr(SIG_FILENAME, signature_b64)

def verify(zip_path, public_key_path):
    # load public key
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    try:
        # retrieve signature from zip content
        with zipfile.ZipFile(zip_path, "r") as zin:
            if SIG_FILENAME not in zin.namelist():
                return False
            
            signature_b64 = zin.read(SIG_FILENAME).decode("utf-8")
            # decode base64 signature back to bytes
            signature = base64.b64decode(signature_b64)

        # recalculate hash of content (excluding the signature file)
        current_content_hash = hash_zip_content(zip_path)
        
        # verify signature
        public_key.verify(
            signature,
            current_content_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True
    except Exception:
        return False
