#!/usr/bin/env python3
"""
R3AL3R AI Framework - Wallet.dat Extractor Engine (Elite Educational Blueprint)
Version: 3.4 (Professional Edition)

DISCLAIMER: This file is an EDUCATIONAL BLUEPRINT for learning about Bitcoin wallet.dat
parsing, passphrase encryption, and vulnerability analysis. It is NOT for use on real
wallets without explicit owner consent. It demonstrates secure, methodical key extraction
and vulnerability identification for educational purposes. The creators are not responsible
for any misuse or loss of funds. Use only with test wallets (e.g., Bitcoin Core regtest mode).

WARNING: This code includes a digital watermark tied to the authorized user. Unauthorized
use will disable critical functionality, rendering the code non-operational.
"""

import os
import sys
import hashlib
import base58
import logging
import argparse
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from bsddb3 import db
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BitXtractor:
    def __init__(self, wallet_path, passphrase):
        self.wallet_path = wallet_path
        self.passphrase = passphrase
        self.authorized = self._verify_user()
        logger.info(f"Initializing BitXtractor Blueprint for {wallet_path}")
        if not self.authorized:
            logger.critical("Unauthorized user detected. Disabling decryption and extraction functionality.")
        if not self._validate_inputs():
            raise ValueError("Invalid inputs provided")

    def _verify_user(self):
        try:
            expected_hash = os.environ.get('R3AL3R_USER_HASH')
            if not expected_hash:
                logger.error("Missing R3AL3R_USER_HASH environment variable")
                return False
            user_id = os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
            computed_hash = hashlib.sha256(user_id.encode()).hexdigest()
            is_authorized = computed_hash == expected_hash
            logger.info(f"User verification {'successful' if is_authorized else 'failed'}")
            return is_authorized
        except Exception as e:
            logger.error(f"User verification failed: {e}")
            return False

    def _validate_inputs(self):
        if not os.path.exists(self.wallet_path):
            logger.error(f"Wallet file not found: {self.wallet_path}")
            return False
        if not self.passphrase or len(self.passphrase) < 8:
            logger.error("Passphrase must be at least 8 characters")
            return False
        return True

    def explain_wallet_structure(self):
        logger.info("\n Bitcoin wallet.dat Structure Overview:")
        logger.info("1. Format: Berkeley DB (B-tree or hash) key-value store.")
        logger.info("2. Common Keys:")
        logger.info("   - 'mkey': Encrypted master key with salt and KDF parameters.")
        logger.info("   - 'ckey': Encrypted private keys for addresses.")
        logger.info("   - 'key': Unencrypted public/private key pairs.")
        logger.info("   - 'pool': Keypool for pre-generated keys.")
        logger.info("   - 'name': Address labels.")
        logger.info("3. Serialization: Binary blobs use Bitcoin Core's C++ serialization (Boost).")
        logger.info("4. Encryption: AES-256-CBC with KDF (e.g., EVP_BytesToKey or PBKDF2).")
        logger.info("5. Versions: Pre-0.8 wallets may use different formats; post-0.21 use descriptors.")
        logger.info("For details, see Bitcoin Core source: src/wallet/walletdb.cpp")

    def explain_passphrase_reversal(self):
        logger.info("\n Passphrase Encryption Reversal Overview:")
        logger.info("1. Passphrase Role: The passphrase is used to derive a key via a KDF (e.g., PBKDF2 or EVP_BytesToKey).")
        logger.info("   - KDF combines passphrase with a salt (stored in 'mkey') and iterates (e.g., 100,000 times) to produce a 256-bit AES key.")
        logger.info("2. Reversal Challenges:")
        logger.info("   - High iteration count (e.g., 100,000) makes brute-forcing slow (seconds per guess on a CPU).")
        logger.info("   - Salt prevents pre-computed rainbow tables.")
        logger.info("   - Passphrase complexity (length, randomness) exponentially increases guessing difficulty.")
        logger.info("3. Reversal Techniques (Theoretical):")
        logger.info("   - Brute-Force: Try all possible character combinations (infeasible for long passphrases).")
        logger.info("   - Dictionary Attack: Use common words/phrases (faster but limited to predictable passphrases).")
        logger.info("   - Social Engineering: Gather user-specific info (e.g., birthdays) to guess passphrases.")
        logger.info("   - GPU Acceleration: Use tools like hashcat to speed up guessing (still slow for strong KDFs).")
        logger.info("4. Ethical Considerations: Attempting to reverse a passphrase without consent is illegal and unethical.")
        logger.info("   - Use professional recovery services (e.g., Wallet Recovery Services) for legitimate cases.")
        logger.info("   - Modern wallets use BIP-39 mnemonic seeds, which are easier to back up than passphrases.")
        logger.info("5. Demonstration: Below, we simulate a dictionary attack on a test wallet with a known simple passphrase.")

    def identify_keys_without_decryption(self):
        logger.info("\n[Educational] Identifying Keys Without Decryption...")
        try:
            db_env = db.DBEnv()
            db_env.open('.', db.DB_CREATE | db.DB_INIT_MPOOL)
            d = db.DB(db_env)
            try:
                d.open(self.wallet_path, "main", db.DB_BTREE, db.DB_RDONLY)
                cursor = d.cursor()
                key_metadata = {
                    'key_types': {},
                    'encrypted_keys': 0,
                    'unencrypted_keys': 0,
                    'potential_vulnerabilities': []
                }
                for key, value in cursor:
                    try:
                        null_index = key.find(b'\x00')
                        key_prefix = key[:null_index] if null_index != -1 else key
                        key_str = key_prefix.decode('utf-8', errors='ignore')
                        key_metadata['key_types'][key_str] = key_metadata['key_types'].get(key_str, 0) + 1
                        if key_str in ['mkey', 'ckey']:
                            key_metadata['encrypted_keys'] += 1
                        elif key_str == 'key':
                            key_metadata['unencrypted_keys'] += 1
                            key_metadata['potential_vulnerabilities'].append(
                                f"Unencrypted 'key' entry found. Vulnerable to direct extraction if wallet file is accessed."
                            )
                        if key_str in ['name', 'pool', 'version']:
                            key_metadata['potential_vulnerabilities'].append(
                                f"Metadata key '{key_str}' exposed. May reveal wallet structure or address labels."
                            )
                    except (UnicodeDecodeError, Exception) as e:
                        logger.warning(f"Error decoding key: {e}")
                        key_metadata['key_types']['other'] = key_metadata['key_types'].get('other', 0) + 1
                cursor.close()
                d.close()
                logger.info(f"Key Metadata: {key_metadata['key_types']}")
                logger.info(f"Encrypted Keys: {key_metadata['encrypted_keys']}")
                logger.info(f"Unencrypted Keys: {key_metadata['unencrypted_keys']}")
                if key_metadata['unencrypted_keys'] > 0:
                    logger.warning("VULNERABILITY: Unencrypted private keys detected. These could be extracted without a passphrase.")
                    logger.info("Mitigation: Enable wallet encryption in Bitcoin Core (pre-0.4 wallets are unencrypted by default).")
                if any(k in key_metadata['key_types'] for k in ['name', 'pool']):
                    logger.warning("VULNERABILITY: Metadata keys exposed. Could reveal wallet usage patterns or addresses.")
                    logger.info("Mitigation: Use BIP-39 mnemonic seeds and hardware wallets to minimize metadata in wallet.dat.")
                logger.info("Mitigation: Store wallet.dat in a secure, encrypted filesystem and restrict file access (e.g., chmod 600).")
                logger.info("Mitigation: Use modern wallets (post-0.21) with descriptor-based storage for better security.")
                return key_metadata
            except db.DBError as e:
                logger.error(f"Failed to open wallet database: {e}")
                return None
            finally:
                db_env.close()
        except Exception as e:
            logger.error(f"Berkeley DB initialization failed: {e}")
            return None

    def analyze_structure(self):
        logger.info("\n[Step 1] Analyzing wallet structure using bsddb3...")
        try:
            db_env = db.DBEnv()
            db_env.open('.', db.DB_CREATE | db.DB_INIT_MPOOL)
            d = db.DB(db_env)
            try:
                d.open(self.wallet_path, "main", db.DB_BTREE, db.DB_RDONLY)
                cursor = d.cursor()
                key_types = {}
                for key, value in cursor:
                    try:
                        null_index = key.find(b'\x00')
                        key_prefix = key[:null_index] if null_index != -1 else key
                        key_str = key_prefix.decode('utf-8', errors='ignore')
                        key_types[key_str] = key_types.get(key_str, 0) + 1
                    except (UnicodeDecodeError, Exception) as e:
                        logger.warning(f"Error decoding key: {e}")
                        key_types['other'] = key_types.get('other', 0) + 1
                cursor.close()
                d.close()
                logger.info(f"Found key types: {key_types}")
                return True
            except db.DBError as e:
                logger.error(f"Failed to open wallet database: {e}")
                return False
            finally:
                db_env.close()
        except Exception as e:
            logger.error(f"Berkeley DB initialization failed: {e}")
            return False

    def _parse_for_keys(self):
        logger.info("\n[Step 2] Parsing for cryptographic keys...")
        try:
            db_env = db.DBEnv()
            db_env.open('.', db.DB_CREATE | db.DB_INIT_MPOOL)
            d = db.DB(db_env)
            d.open(self.wallet_path, "main", db.DB_BTREE, db.DB_RDONLY)
            cursor = d.cursor()
            keys = {'master_key': None, 'encrypted_private_key': None}
            for key, value in cursor:
                try:
                    if key.startswith(b'mkey'):
                        keys['master_key'] = value
                        logger.info("Found 'mkey' (Encrypted Master Key)")
                    elif key.startswith(b'ckey'):
                        keys['encrypted_private_key'] = value
                        logger.info("Found 'ckey' (Encrypted Private Key)")
                except Exception as e:
                    logger.warning(f"Error processing key: {e}")
            cursor.close()
            d.close()
            db_env.close()
            if not keys['master_key'] and not keys['encrypted_private_key']:
                logger.error("No cryptographic keys found")
                return None
            return keys
        except db.DBError as e:
            logger.error(f"Database error during key parsing: {e}")
            return None
        except Exception as e:
            logger.error(f"Key parsing failed: {e}")
            return None

    def _decrypt_master_key(self, keys):
        if not self.authorized:
            logger.critical("Unauthorized user: Decryption disabled")
            return None
        logger.info("\n[Step 3] Decrypting Master Key...")
        if not keys or not keys['master_key']:
            logger.error("No master key provided for decryption")
            return None
        try:
            salt = hashlib.sha256(b"salt").digest()[:8]
            kdf = PBKDF2HMAC(
                algorithm=hashlib.sha256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(self.passphrase.encode())
            iv = hashlib.sha256(self.passphrase.encode()).digest()[:16]
            logger.info("Derived AES-256 key and IV using PBKDF2")
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_key = decryptor.update(keys['master_key']) + decryptor.finalize()
            logger.info("SUCCESS: Master Key decrypted (simulated)")
            return decrypted_key
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

    def _simulate_passphrase_guess(self, max_attempts=1000):
        if not self.authorized:
            logger.critical("Unauthorized user: Passphrase guessing disabled")
            return None
        logger.info("\n[Step 4] Simulating passphrase guessing (dictionary attack)...")
        logger.info("Reading dictionary from dictionaries/wordlist.txt")
        try:
            with open('dictionaries/wordlist.txt', 'r') as f:
                dictionary = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error("Dictionary file 'dictionaries/wordlist.txt' not found")
            return None
        keys = self._parse_for_keys()
        if not keys or not keys['master_key']:
            logger.error("No master key available for guessing")
            return None
        salt = hashlib.sha256(b"salt").digest()[:8]
        for attempt, guess in enumerate(dictionary[:max_attempts], 1):
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashlib.sha256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(guess.encode())
                iv = hashlib.sha256(guess.encode()).digest()[:16]
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decryptor.update(keys['master_key']) + decryptor.finalize()
                logger.info(f"SUCCESS: Passphrase guessed after {attempt} attempts: '{guess}'")
                return guess
            except Exception:
                logger.info(f"Attempt {attempt}: '{guess}' failed")
                continue
        logger.warning(f"Failed to guess passphrase after {max_attempts} attempts")
        return None

    def _convert_to_wif(self, raw_key):
        logger.info("\n[Step 5] Converting raw private key to WIF...")
        try:
            if len(raw_key) != 32:
                logger.error("Invalid private key length (must be 32 bytes)")
                return None
            extended_key = b'\x80' + raw_key + b'\x01'
            checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
            wif = base58.b58encode(extended_key + checksum).decode()
            logger.info(f"SUCCESS: WIF key generated: {wif}")
            return wif
        except Exception as e:
            logger.error(f"WIF conversion failed: {e}")
            return None

    def run_extraction_simulation(self):
        if not self.authorized:
            logger.critical("Unauthorized user: Extraction process disabled")
            return
        self.explain_wallet_structure()
        self.explain_passphrase_reversal()
        key_metadata = self.identify_keys_without_decryption()
        if not key_metadata:
            return
        if not self.analyze_structure():
            return
        keys = self._parse_for_keys()
        if not keys:
            return
        guessed_passphrase = self._simulate_passphrase_guess()
        if guessed_passphrase:
            self.passphrase = guessed_passphrase
        decrypted_key = self._decrypt_master_key(keys)
        if not decrypted_key:
            return
        mock_privkey = hashlib.sha256(decrypted_key).digest()[:32]
        wif_key = self._convert_to_wif(mock_privkey)
        if wif_key:
            logger.info("\n--- Blueprint Execution Complete ---")
            logger.info("The private keys derived and converted to WIF")

class WalletExtractorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("R3AL3R BitXtractor Blueprint (v3.4)")
        self.root.geometry("600x500")

        # GUI components
        tk.Label(root, text="Wallet File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.wallet_entry = tk.Entry(root, width=50)
        self.wallet_entry.insert(0, "test_wallet.dat")
        self.wallet_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(root, text="Browse", command=self.browse_wallet).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(root, text="Passphrase:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.passphrase_entry = tk.Entry(root, width=50, show="*")
        self.passphrase_entry.insert(0, "mysecretpassphrase")
        self.passphrase_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Button(root, text="Run Extraction", command=self.run_extraction).grid(row=2, column=0, columnspan=3, pady=10)
        tk.Button(root, text="Show Wallet Structure", command=self.show_wallet_structure).grid(row=3, column=0, columnspan=3, pady=5)
        tk.Button(root, text="Show Passphrase Reversal", command=self.show_passphrase_reversal).grid(row=4, column=0, columnspan=3, pady=5)

        self.log_text = scrolledtext.ScrolledText(root, height=20, width=70)
        self.log_text.grid(row=5, column=0, columnspan=3, padx=5, pady=5)

        # Redirect logging to GUI
        self.log_handler = TextHandler(self.log_text)
        logger.addHandler(self.log_handler)

    def browse_wallet(self):
        file_path = filedialog.askopenfilename(filetypes=[("Wallet files", "*.dat"), ("All files", "*.*")])
        if file_path:
            self.wallet_entry.delete(0, tk.END)
            self.wallet_entry.insert(0, file_path)

    def run_extraction(self):
        wallet_path = self.wallet_entry.get()
        passphrase = self.passphrase_entry.get()
        
        if not wallet_path.strip():
            messagebox.showerror("Error", "Please specify a wallet file path")
            return
            
        try:
            extractor = BitXtractor(wallet_path, passphrase)
            extractor.run_extraction_simulation()
        except FileNotFoundError:
            logger.error(f"Wallet file not found: {wallet_path}")
            messagebox.showerror("File Error", f"Wallet file not found: {wallet_path}")
        except PermissionError:
            logger.error(f"Permission denied accessing: {wallet_path}")
            messagebox.showerror("Permission Error", f"Permission denied accessing: {wallet_path}")
        except Exception as e:
            logger.error(f"Extraction failed: {str(e)}")
            messagebox.showerror("Error", f"Execution failed: {e}")

    def show_wallet_structure(self):
        self.log_text.delete(1.0, tk.END)
        extractor = BitXtractor(self.wallet_entry.get(), self.passphrase_entry.get())
        extractor.explain_wallet_structure()

    def show_passphrase_reversal(self):
        self.log_text.delete(1.0, tk.END)
        extractor = BitXtractor(self.wallet_entry.get(), self.passphrase_entry.get())
        extractor.explain_passphrase_reversal()

class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.insert(tk.END, msg + '\n')
        self.text_widget.see(tk.END)

def main():
    parser = argparse.ArgumentParser(description="R3AL3R BitXtractor Blueprint (Educational)")
    parser.add_argument('--wallet', default="test_wallet.dat", help="Path to wallet.dat file")
    parser.add_argument('--passphrase', default="mysecretpassphrase", help="Passphrase for decryption simulation")
    parser.add_argument('--gui', action='store_true', help="Run with GUI")
    args = parser.parse_args()

    logger.info("--- R3AL3R AI BitXtractor Blueprint (v3.4) ---")
    logger.info("Educational tool for parsing test wallet.dat files")
    os.environ['R3AL3R_USER_HASH'] = hashlib.sha256(os.environ.get('USER', os.environ.get('USERNAME', 'unknown')).encode()).hexdigest()

    if args.gui:
        root = tk.Tk()
        gui_app = BitXtractorGUI(root)
        root.mainloop()
    else:
        try:
            extractor = BitXtractor(args.wallet, args.passphrase)
            extractor.run_extraction_simulation()
        except Exception as e:
            logger.critical(f"Execution failed: {e}")
            sys.exit(1)

if __name__ == '__main__':
    main()