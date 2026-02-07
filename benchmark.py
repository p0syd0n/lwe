import subprocess
import re
from decimal import Decimal, getcontext

# Set precision high enough to handle 12+ decimal places safely
getcontext().prec = 25

# --- Configuration ---
CARGO_CMD = ["cargo", "run", "--release", "--quiet"]
FILENAME = "key.txt"
ITERATIONS = 100
KEY_SIZE_BYTES = 32

def generate_openssl_key(n_bytes):
    """Generates an N-byte hex string using OpenSSL."""
    result = subprocess.run(
        ["openssl", "rand", "-hex", str(n_bytes)],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()

def run_lwe_command(choice, input_str=None):
    """Interacts with the Rust binary's menu system."""
    process = subprocess.Popen(
        CARGO_CMD,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    full_input = f"{choice}\n"
    if input_str:
        full_input += f"{input_str}\n"
    
    stdout, _ = process.communicate(input=full_input)
    return stdout

def extract_time_precise(output):
    """Extracts seconds from output as a high-precision Decimal."""
    match = re.search(r"in ([\d.]+) seconds", output)
    if match:
        return Decimal(match.group(1))
    return None

# --- Main Benchmark Loop ---
enc_times = []
dec_times = []

print(f"--- Starting Benchmark ({ITERATIONS} iterations) ---")
print(f"--- Generating {KEY_SIZE_BYTES} byte AES keys via OpenSSL ---")

for i in range(ITERATIONS):
    # 1. Generate key and write to file
    new_plaintext = generate_openssl_key(KEY_SIZE_BYTES)
    with open(FILENAME, "w") as f:
        f.write(new_plaintext)
    
    # 2. Generate new LWE Keys
    run_lwe_command("3")
    
    # 3. Encrypt
    enc_output = run_lwe_command("1", FILENAME)
    e_time = extract_time_precise(enc_output)
    if e_time is not None: 
        enc_times.append(e_time)
    
    # 4. Decrypt
    dec_output = run_lwe_command("2", FILENAME)
    d_time = extract_time_precise(dec_output)
    if d_time is not None: 
        dec_times.append(d_time)
    
    # Simple progress tracker
    if (i + 1) % 10 == 0:
        print(f"Progress: {i+1}/{ITERATIONS} iterations complete...")

# --- Final High-Precision Output ---
print("\n" + "="*45)
print(f"ENCRYPTION TIMES (seconds, 12 decimal places):")
print("-" * 45)
for t in enc_times:
    print(f"{t:.12f}")

print("\nDECRYPTION TIMES (seconds, 12 decimal places):")
print("-" * 45)
for t in dec_times:
    print(f"{t:.12f}")

if enc_times and dec_times:
    avg_enc = sum(enc_times) / len(enc_times)
    avg_dec = sum(dec_times) / len(dec_times)
    print("\n" + "="*45)
    print(f"AVG ENCRYPT: {avg_enc:.12f}s")
    print(f"AVG DECRYPT: {avg_dec:.12f}s")
    print("="*45)