import zipfile
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

# Nama file signature di dalam ZIP
SIG_FILENAME = "mod_signature.sig"

def generate_keys():
    """
    Generate pasangan Private Key dan Public Key (RSA 2048-bit).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Simpan Private Key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Simpan Public Key
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("[INFO] Kunci berhasil dibuat: private_key.pem dan public_key.pem")

def calculate_zip_content_hash(zip_path):
    """
    Menghitung hash dari ISI file zip (mengabaikan file signature jika ada).
    """
    hasher = hashes.Hash(hashes.SHA256())
    
    with zipfile.ZipFile(zip_path, 'r') as zin:
        # PENTING: Urutkan nama file agar urutan hash selalu konsisten (deterministik)
        file_list = sorted(zin.namelist())
        
        for filename in file_list:
            # Skip file signature agar tidak terjadi looping hash
            if filename == SIG_FILENAME:
                continue
                
            # Update hash dengan nama file (untuk mencegah rename attack)
            hasher.update(filename.encode('utf-8'))
            
            # Update hash dengan isi file
            with zin.open(filename) as f:
                hasher.update(f.read())
                
    return hasher.finalize()

def sign_mod(zip_path, private_key_path):
    """
    Membuat signature dari konten ZIP dan menyisipkannya ke dalam ZIP tersebut.
    """
    # 1. Load Private Key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    print(f"[PROCESS] Menghitung hash konten untuk {zip_path}...")
    # 2. Hitung Hash dari konten ZIP yang ada saat ini
    content_hash = calculate_zip_content_hash(zip_path)

    # 3. Buat Digital Signature
    # signature = private_key.sign(
    #     content_hash,
    #     padding.PSS(
    #         mgf=padding.MGF1(hashes.SHA256()),
    #         salt_length=padding.PSS.MAX_LENGTH
    #     ),
    #     utils=hashes.SHA256() # Prehashed=True tidak dipakai di sini karena kita pass digest bytes langsung? 
    #     # Koreksi: Library cryptography modern mengharapkan data asli untuk di-hash internal 
    #     # atau kita gunakan Prehashed jika sudah punya digest.
    #     # Mari gunakan cara standar: sign data (hash bytes) dengan Prehashed class
    # )
    
    # Koreksi implementasi sign agar kompatibel dengan content_hash yang berupa bytes
    signature = private_key.sign(
        content_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 4. Masukkan signature ke dalam ZIP
    # Mode 'a' (append) menambahkan file tanpa menghapus isi zip
    with zipfile.ZipFile(zip_path, 'a') as zout:
        zout.writestr(SIG_FILENAME, signature)
        
    print(f"[SUCCESS] Signature berhasil ditambahkan ke dalam {zip_path} ({SIG_FILENAME})")

def verify_mod(zip_path, public_key_path):
    """
    Memverifikasi signature di dalam ZIP terhadap kontennya.
    """
    # 1. Load Public Key
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    try:
        # 2. Ambil signature dari dalam ZIP
        with zipfile.ZipFile(zip_path, 'r') as zin:
            if SIG_FILENAME not in zin.namelist():
                print("[ERROR] File signature tidak ditemukan dalam archive.")
                return False
            signature = zin.read(SIG_FILENAME)

        # 3. Hitung ulang hash konten (tanpa menyertakan file signature)
        # Ini mensimulasikan "File mod tanpa signature"
        current_content_hash = calculate_zip_content_hash(zip_path)

        # 4. Verifikasi
        public_key.verify(
            signature,
            current_content_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[VALID] Signature VALID. Mod aman digunakan.")
        return True

    except Exception as e:
        print(f"[INVALID] Verifikasi GAGAL! File mungkin telah dimodifikasi. Error: {e}")
        return False

# --- Main Program untuk Testing ---
if __name__ == "__main__":
    # Contoh penggunaan sederhana
    print("--- 1. GENERATE KEYS ---")
    generate_keys()
    
    # Buat dummy zip jika belum ada
    mod_zip = input("Masukkan file path mod (misal: test/my_mod.zip): ")

    print(f"\n--- 2. SIGNING {mod_zip} ---")
    sign_mod(mod_zip, "private_key.pem")

    print(f"\n--- 3. VERIFYING {mod_zip} ---")
    verify_mod(mod_zip, "public_key.pem")

    print("\n--- 4. TEST TAMPERING (Percobaan Modifikasi Ilegal) ---")
    # Kita coba ubah isi zip tanpa sign ulang
    with zipfile.ZipFile(mod_zip, 'a') as z:
        z.writestr("hack.txt", "Malicious code")
    print("File zip telah dimodifikasi (disisipi file hack.txt).")
    
    verify_mod(mod_zip, "public_key.pem")
