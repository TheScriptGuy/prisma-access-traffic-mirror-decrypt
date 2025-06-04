import argparse
import base64
import json
import logging
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
import sys # Added for sys.exit

# Cryptography imports
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as rsa_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Embedded file I/O functions ---
def read_file_content(file_path: Path) -> bytes | None:
    """Reads a file and returns its content as bytes."""
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        return file_content
    except Exception as e:
        logging.error(f"Read file error for '{file_path}': {e}")
        return None

def write_file(file_path: Path, file_content: bytes) -> bool:
    """Writes byte content to a file, creating parent directories if needed."""
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'wb') as f:
            f.write(file_content)
        return True
    except Exception as e:
        logging.error(f"Write file error for '{file_path}': {e}")
        return False

# --- Core AES-GCM Decryption Logic ---
def aes_gcm_decrypt(encrypted_data_bytes: bytes, aes_key_b64: str, aes_nonce_b64: str, aes_tag_b64: str) -> bytes | None:
    """Decrypts AES-GCM encrypted data and verifies the authentication tag."""
    try:
        key = base64.b64decode(aes_key_b64)
        nonce = base64.b64decode(aes_nonce_b64)
        tag_to_verify = base64.b64decode(aes_tag_b64)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag_to_verify), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(encrypted_data_bytes) + decryptor.finalize()
        return plaintext_bytes
    except InvalidTag:
        logging.error("AES-GCM decryption failed: The authentication tag is invalid. "
                      "Data may be tampered, or key/nonce/tag incorrect.")
        return None
    except Exception as e:
        logging.error(f"An unexpected AES-GCM decryption error occurred: {e}")
        return None

# --- Main Cryptographic Logic (for one set of files) ---
def decrypt_file_set(
    source_enc_filepath: Path,
    source_key_material_filepath: Path,
    private_key_pem_path: Path,
    target_decrypted_filepath: Path
) -> bool:
    """Processes a single set: decrypts an ENC file using its key material file."""
    logging.info(f"Processing set: ENC='{source_enc_filepath.name}', KEY_MATERIAL='{source_key_material_filepath.name}'")

    private_key_obj = None
    detected_key_type = "Unknown"
    try:
        private_key_bytes = read_file_content(private_key_pem_path)
        if private_key_bytes is None: return False
        private_key_obj = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
        if isinstance(private_key_obj, rsa.RSAPrivateKey): detected_key_type = "RSA"
        elif isinstance(private_key_obj, ec.EllipticCurvePrivateKey): detected_key_type = "Elliptic Curve"
        logging.debug(f"Private key loaded. Type: {detected_key_type}.")
    except Exception as e:
        logging.error(f"Failed to load/identify private key from '{private_key_pem_path}': {e}")
        return False

    key_material_bytes = read_file_content(source_key_material_filepath)
    if key_material_bytes is None: return False

    json_str = ""
    aes_params_source = ""
    try:
        json_str = key_material_bytes.decode('utf-8')
        json.loads(json_str)
        aes_params_source = "plaintext"
        logging.debug(f"Key material '{source_key_material_filepath.name}' is plaintext JSON.")
    except (UnicodeDecodeError, json.JSONDecodeError):
        logging.debug(f"Key material '{source_key_material_filepath.name}' not plaintext JSON. Attempting RSA decryption.")
        if detected_key_type == "RSA":
            try:
                dec_bytes = private_key_obj.decrypt(
                    key_material_bytes,
                    rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                json_str = dec_bytes.decode('utf-8')
                json.loads(json_str)
                aes_params_source = "RSA-decrypted"
                logging.debug(f"Successfully RSA-decrypted '{source_key_material_filepath.name}'.")
            except Exception as rsa_e:
                logging.error(f"RSA decryption of '{source_key_material_filepath.name}' failed: {rsa_e}")
                return False
        else:
            logging.error(f"Key material not plaintext and private key ('{detected_key_type}') is not RSA. Cannot decrypt '{source_key_material_filepath.name}'.")
            return False
    if not json_str: return False

    try:
        sym_key_data = json.loads(json_str)
        aes_key_b64, aes_nonce_b64, aes_tag_b64 = sym_key_data['key'], sym_key_data['nonce'], sym_key_data['tag']
    except (json.JSONDecodeError, KeyError) as e:
        logging.error(f"Failed to parse {aes_params_source} key material JSON or missing keys ('key'/'nonce'/'tag') in '{source_key_material_filepath.name}': {e}")
        return False

    main_ciphertext_bytes = read_file_content(source_enc_filepath)
    if main_ciphertext_bytes is None: return False

    decrypted_data = aes_gcm_decrypt(main_ciphertext_bytes, aes_key_b64, aes_nonce_b64, aes_tag_b64)
    if decrypted_data is None:
        logging.error(f"AES-GCM decryption failed for '{source_enc_filepath.name}'.")
        return False
    logging.info(f"Successfully decrypted '{source_enc_filepath.name}'.")

    if write_file(target_decrypted_filepath, decrypted_data):
        logging.info(f"Decrypted output written to '{target_decrypted_filepath}'.")
        return True
    return False

# --- ZIP and Directory Processing Logic ---
def process_single_zip(
    zip_file_path: Path,
    private_key_path: Path,
    global_output_dir_path: Path | None,
    on_missing_files_decision: str,
    is_batch_mode: bool
) -> str:
    logging.info(f"Processing ZIP: '{zip_file_path.name}'")

    effective_output_dir = global_output_dir_path if global_output_dir_path else zip_file_path.parent
    effective_output_dir.mkdir(parents=True, exist_ok=True)

    current_decision_for_this_zip = on_missing_files_decision

    try:
        with tempfile.TemporaryDirectory(dir=str(effective_output_dir), prefix=f".{zip_file_path.stem}_extract_") as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            logging.debug(f"Created temporary extraction directory: {temp_dir}")

            try:
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    zip_ref.extractall(path=temp_dir)
                    logging.debug(f"Extracted all members from '{zip_file_path.name}' to '{temp_dir}'.")
            except zipfile.BadZipFile:
                logging.error(f"'{zip_file_path.name}' is not valid or corrupted. Skipping.")
                return current_decision_for_this_zip
            except Exception as e:
                logging.error(f"Failed to extract '{zip_file_path.name}': {e}. Skipping.")
                return current_decision_for_this_zip

            pcap_enc_files = list(temp_dir.rglob("*.pcap.enc"))
            pcapng_enc_files = list(temp_dir.rglob("*.pcapng.enc"))
            all_found_enc_files = set(pcap_enc_files)
            all_found_enc_files.update(pcapng_enc_files)
            enc_files_in_temp = sorted(list(all_found_enc_files))

            if not enc_files_in_temp:
                logging.warning(f"No '*.pcap.enc' or '*.pcapng.enc' files found in extracted content of '{zip_file_path.name}'.")
                return current_decision_for_this_zip

            info_file_in_temp = temp_dir / "info.txt"
            if not info_file_in_temp.is_file(): info_file_in_temp = None
            if info_file_in_temp: logging.debug(f"'info.txt' found and extracted to '{info_file_in_temp}'.")

            sets_processed_in_zip = 0
            for enc_filepath_in_temp in enc_files_in_temp:
                if is_batch_mode and current_decision_for_this_zip == "abort_all_on_problem":
                    logging.info("Aborting processing of further sets in this ZIP due to 'abort all' decision.")
                    break

                base_stem = enc_filepath_in_temp.stem
                json_filename = base_stem + ".json"
                json_filepath_in_temp = enc_filepath_in_temp.parent / json_filename

                if not json_filepath_in_temp.is_file():
                    logging.warning(f"Required key material '{json_filename}' not found for '{enc_filepath_in_temp.name}' in ZIP '{zip_file_path.name}'.")
                    if is_batch_mode:
                        if current_decision_for_this_zip == "skip_problematic":
                            logging.info(f"Skipping set '{enc_filepath_in_temp.name}' (user preference: always skip).")
                            continue
                        while True:
                            print("-" * 30)
                            user_choice = input(
                                f"Problem in ZIP '{zip_file_path.name}', set '{enc_filepath_in_temp.name}':\n"
                                f"  Required key material file '{json_filename}' is missing.\n"
                                f"Choose: (A)bort all processing, (S)kip this problematic set, (K)eep skipping ALL future problematic sets? [A/S/K]: "
                            ).upper()
                            if user_choice == 'A':
                                logging.info("User chose to ABORT ALL processing.")
                                current_decision_for_this_zip = "abort_all_on_problem"
                                break
                            elif user_choice == 'S':
                                logging.info(f"User chose to SKIP THIS SET ('{enc_filepath_in_temp.name}').")
                                break
                            elif user_choice == 'K':
                                logging.info("User chose to KEEP SKIPPING all future problematic sets.")
                                current_decision_for_this_zip = "skip_problematic"
                                break
                            else:
                                print("Invalid choice.")
                        if current_decision_for_this_zip == "abort_all_on_problem": break
                        if user_choice in ['S', 'K']: continue
                    else:
                        logging.error(f"Required file '{json_filename}' missing for '{enc_filepath_in_temp.name}'. Aborting for this ZIP.")
                        return "abort_all_on_problem"

                decrypted_output_filename = base_stem
                final_decrypted_path = effective_output_dir / decrypted_output_filename

                success = decrypt_file_set(enc_filepath_in_temp, json_filepath_in_temp, private_key_path, final_decrypted_path)
                if success:
                    sets_processed_in_zip += 1
                    if info_file_in_temp:
                        target_info_filename = base_stem + ".info.txt"
                        target_info_path = effective_output_dir / target_info_filename
                        logging.debug(f"Copying 'info.txt' to '{target_info_path}' for set '{base_stem}'.")
                        if target_info_path.exists():
                            logging.warning(f"Overwriting existing info file: '{target_info_path}'.")
                        shutil.copy2(info_file_in_temp, target_info_path)

            if sets_processed_in_zip > 0:
                logging.info(f"Finished ZIP '{zip_file_path.name}'. Successfully processed {sets_processed_in_zip} set(s).")
            elif enc_files_in_temp:
                logging.warning(f"No sets successfully processed in ZIP '{zip_file_path.name}'.")

    except Exception as e: # Catches errors like permission issues with tempfile.TemporaryDirectory
        logging.error(f"Unexpected error during setup or cleanup for ZIP '{zip_file_path.name}': {e}", exc_info=True)
        if not is_batch_mode : return "abort_all_on_problem"
    return current_decision_for_this_zip


def process_directory(
    directory_path: Path,
    private_key_path: Path,
    global_output_dir_path: Path | None,
    initial_on_missing_files_decision: str
):
    logging.info(f"Scanning directory: '{directory_path}'")
    current_batch_decision = initial_on_missing_files_decision

    zip_files = sorted([f for f in directory_path.iterdir() if f.is_file() and f.suffix.lower() == '.zip'])

    if not zip_files:
        logging.info(f"No ZIP files found in '{directory_path}'.")
        return

    logging.info(f"Found {len(zip_files)} ZIP file(s) for potential processing.")
    for i, zip_file_path in enumerate(zip_files):
        if current_batch_decision == "abort_all_on_problem":
            logging.warning("Aborting further directory processing due to 'abort all' decision.")
            break

        if not zipfile.is_zipfile(zip_file_path):
            logging.warning(f"Skipping '{zip_file_path.name}': Not a valid ZIP file.")
            continue

        logging.info(f"--- Processing ZIP {i+1}/{len(zip_files)}: '{zip_file_path.name}' ---")
        current_batch_decision = process_single_zip(
            zip_file_path, private_key_path, global_output_dir_path, current_batch_decision, is_batch_mode=True
        )
    logging.info(f"Finished processing directory '{directory_path}'.")

def process_input_source(
    input_path: Path,
    private_key_path: Path,
    global_output_dir_path: Path | None,
    initial_on_missing_files_decision: str
):
    if not input_path.exists():
        logging.error(f"Input path '{input_path}' does not exist. Aborting.")
        return

    if input_path.is_dir():
        process_directory(input_path, private_key_path, global_output_dir_path, initial_on_missing_files_decision)
    elif input_path.is_file():
        if input_path.suffix.lower() == '.zip' and zipfile.is_zipfile(input_path):
            process_single_zip(input_path, private_key_path, global_output_dir_path, initial_on_missing_files_decision, is_batch_mode=False)
        else:
            logging.error(f"Input file '{input_path}' is not a valid ZIP file. Aborting.")
    else:
        logging.error(f"Input path '{input_path}' is not a recognized file or directory. Aborting.")

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(
        description="Decrypts AES-GCM encrypted capture files (.pcap.enc, .pcapng.enc) from ZIP archives. "
                    "Key material (JSON with 'key', 'nonce', 'tag') can be plaintext or RSA-encrypted within ZIP. "
                    "Supports RSA/EC private keys for decrypting RSA-encrypted key material."
    )
    parser.add_argument("private_key_path", type=Path,
                        help="Path to your PEM-encoded private key file (RSA or EC). "
                             "An RSA key is required if key material files are RSA-encrypted.")
    parser.add_argument("input_path", type=Path,
                        help="Path to a single ZIP file or a directory containing ZIP files to process.")
    parser.add_argument("--output-dir", "-o", type=Path, default=None,
                        help="Directory to store decrypted files and info files. "
                             "Defaults to same location as input ZIP(s). Created if it doesn't exist.")
    parser.add_argument("--on-missing-files", choices=['prompt', 'skip_problematic', 'abort_all_on_problem'],
                        default='prompt',
                        help="Batch mode: behavior when required files for a decryption set (e.g., .json key material) are missing within a ZIP. "
                             "Default: 'prompt'. 'skip_problematic' will skip such sets. 'abort_all_on_problem' will stop all processing.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging for verbose output.")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    exit_code = 0
    try:
        logging.info("Script starting...")
        if not args.private_key_path.is_file():
            logging.critical(f"Private key file not found: {args.private_key_path}")
            return 1

        if args.output_dir:
            try:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                logging.info(f"Output directory set to: {args.output_dir}")
            except Exception as e:
                logging.critical(f"Could not create or access output directory '{args.output_dir}': {e}")
                return 1

        process_input_source(args.input_path, args.private_key_path, args.output_dir, args.on_missing_files)
        logging.info("Script processing finished.")

    except KeyboardInterrupt:
        logging.warning("\n\nProcess interrupted by user (Ctrl+C). Exiting...")
        exit_code = 130
    except Exception as e:
        logging.critical(f"An unexpected critical error occurred at the main level: {e}", exc_info=True)
        exit_code = 2

    return exit_code

if __name__ == '__main__':
    sys.exit(main())
