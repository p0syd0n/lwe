use faer::Mat;
use rand::prelude::*;
use rand::rng;
use rand_distr::{Normal, Distribution};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::time::Instant;
use std::io;

// hyperparameters
const N: usize = 256; // Number of coefficients in vectors, also number of samples
const Q: f64 = (N*N*N) as f64; // Modulus
const STDEV:f64 = (Q/4.0)/(N*N) as f64;

fn gauss_error() -> f64 {
    let normal = Normal::new(0.0, STDEV).unwrap();
    let mut rng = rng();
    let sample = normal.sample(&mut rng);
     println!("[gauss_error] Sampled noise e = {:.4}", sample);
    sample
}

fn gen_key() -> (Mat<f64>, Mat<f64>) {
    // println!("\n=== Generating keys ===");
    let mut rng = rand::rng();

    // Private key
    let mut private_key = Mat::<f64>::zeros(1, N);
    for coefficient in 0..N {
        private_key[(0, coefficient)] = rng.random_range(1..Q as i64) as f64;
    }
    // println!("[gen_key] Private key s = {:?}", private_key);

    // Public key matrix
    let mut public_key = Mat::<f64>::zeros(N, N + 1);
    for row in 0..N {
        let mut cumulative_b: f64 = 0.0;
        // println!("\n[gen_key] Generating equation {}:", row);
        for column in 0..N {
            let choice = rng.random_range(1..Q as i64) as f64;
            public_key[(row, column)] = choice;
            cumulative_b += choice * private_key[(0, column)];
            cumulative_b = cumulative_b.rem_euclid(Q);
            // println!(
            //     "    A[{},{}] = {:.2}, s[{}] = {:.2} → partial cumulative_b = {:.2}",
            //     row, column, choice, column, private_key[(0, column)], cumulative_b
            // );
        }
        let error = gauss_error();
        cumulative_b += error;
        cumulative_b = cumulative_b.rem_euclid(Q);
        public_key[(row, N)] = cumulative_b;
        // println!("    Added noise {:.4} → b = {:.4} (mod {:.0})", error, cumulative_b, Q);
    }

    // println!("\n[gen_key] Public key A|b = {:?}", public_key);
    // println!("=========================\n");

    (private_key, public_key)
}

fn split_u32_to_bits(value: u32) -> Vec<bool> {
    let mut bits = Vec::with_capacity(32);
    for i in 0..32 {
        // Check if the i-th bit is set
        // (value >> i) shifts the bit to the least significant position
        // & 1 checks if that bit is a 1
        let is_set = ((value >> i) & 1) == 1;
        bits.push(is_set);
    }
    bits.reverse(); // Reverse to get bits in big-endian order (most significant first)
    bits
}

fn bits_to_u32(bits: Vec<bool>) -> u32 {
    let mut value = 0u32;

    for &bit in bits.iter() {
        value <<= 1;
        if bit {
            value |= 1;
        }
    }

    value
}


fn encrypt(public_key: &Mat<f64>, bit: bool) -> String {

    println!("=== Encrypting ===");
    let mut rng = rand::rng();

    // Randomly choose subset of equations
    let num_equations = rng.random_range(2..=N);
    println!("[encrypt] Using {:?} equations", num_equations);
    let mut equations_used = Vec::<usize>::new();
    for _ in 0..num_equations {
        let chosen = rng.random_range(0..N);
        equations_used.push(chosen.try_into().unwrap());
    }

    println!("[encrypt] Using equations {:?}", equations_used);

    // Compute sum of chosen equations
    let mut final_vector = vec![0.0; N + 1];
    for &chosen_equation in &equations_used {
        for column in 0..(N + 1) {
            final_vector[column] += (*public_key)[(chosen_equation, column)];
        }
    }

    for column in 0..(N + 1) {
        final_vector[column] = (final_vector[column]).rem_euclid(Q);
    }
    
    println!("[encrypt] Summed vector (before bit) = {:?}", final_vector);

    // Embed message bit
    if bit {
        final_vector[N] += (Q as i64 / 2) as f64;
        println!("THe ciphertext before modding: {}", final_vector[N]);
        final_vector[N] = final_vector[N].rem_euclid(Q);
        println!("[encrypt] Added Q/2 ({}) for bit=1 → b' = {:.2}", (Q as i64 / 2) as f64, final_vector[N]);
    } else {
        println!("[encrypt] Bit = 0 (no offset added)");
    }

    // Convert to ciphertext string
    let mut ciphertext = String::new();
    ciphertext.push('(');
    for (index, item) in final_vector.iter().enumerate() {
        ciphertext.push_str(&item.to_string());
        if index != N {
            ciphertext.push_str(", ");
        }
    }
    ciphertext.push(')');
    println!("[encrypt] Ciphertext = {}", ciphertext);
    println!("===================\n");

    ciphertext
}

fn decrypt(private_key: &Mat<f64>, ciphertext: String) -> bool {
    println!("=== Decrypting ===");
    println!("[decrypt] Ciphertext = {}", ciphertext);

    // Parse ciphertext "(x, y, z)"
    let middle: String = ciphertext.chars().skip(1).take(ciphertext.len() - 2).collect();
    let ciphertext_vectorized_string: Vec<&str> = middle.split(", ").collect();
    println!(
        "[decrypt] Parsed components (strings): {:?}",
        ciphertext_vectorized_string
    );

    // Convert to floats
    let mut ciphertext_vectorized: Vec<f64> = vec![];
    for number in ciphertext_vectorized_string {
        match number.parse::<f64>() {
            Ok(result) => ciphertext_vectorized.push(result),
            Err(_) => panic!("[decrypt] Failed to parse ciphertext component."),
        }
    }
    println!("[decrypt] Ciphertext vector = {:?}", ciphertext_vectorized);

    // Compute dot product a·s
    let mut cumulative_b: f64 = 0.0;
    for (index, column) in ciphertext_vectorized[..ciphertext_vectorized.len() - 1]
        .iter()
        .enumerate()
    {
        cumulative_b += column * (*private_key)[(0, index)];
        println!(
            "    step {}: column={:.2}, s={:.2} → partial cumulative_b={:.2}",
            index, column, private_key[(0, index)], cumulative_b
        );
    }
    cumulative_b = cumulative_b.rem_euclid(Q);

    let received_b = ciphertext_vectorized[ciphertext_vectorized.len() - 1];
    
    let q_f64 = Q as f64;
    // Boundary 1: Q/4
    let q_quarter = q_f64 / 4.0;
    // Boundary 2: 3Q/4
    let q_three_quarters = 3.0 * q_f64 / 4.0;

    // 1. Calculate the raw difference (noisy signal) in the range [0, Q).
    // This value, raw_diff, is what we compare against the boundaries.
    let raw_diff = (received_b - cumulative_b).rem_euclid(q_f64);
    println!("The recieved-cumulative = {}-{}={}==={}", received_b, cumulative_b, received_b-cumulative_b, raw_diff);
    
    // 2. Decide the bit:
    // Bit is 1 if raw_diff is in the Q/2 neighborhood [Q/4, 3Q/4].
    // Otherwise, the bit is 0 (it's in the 0 neighborhood, [0, Q/4) or (3Q/4, Q)).
    let bit: bool = if raw_diff >= q_quarter && raw_diff <= q_three_quarters {
        true
    } else {
        false
    };
    println!("[decrypt] Decrypted bit = {}\n", bit);
    bit
}

fn encrypt_text(text: String, public_key: &Mat<f64>) -> String {
    let mut final_ciphertext: String = Default::default();
    for character in text.chars() {
        let intvalue = character as u32;
        let bits = split_u32_to_bits(intvalue);
        println!("Encrypt_text, encrypting {} bits in a single characte: ", bits.len());
        println!("{:?}", bits);
        //panic!();
        for bit in bits {
            let encrypted = encrypt(public_key, bit);
            final_ciphertext.push_str(&encrypted);
            final_ciphertext.push_str("+");
        }
    }
    final_ciphertext
}

fn decrypt_text(text: String, private_key: &Mat<f64>) -> String {
    println!("Derypting onecharacter");
    let mut string_plaintext: String = Default::default();
    let mut split_ciphertext = text.split("+").collect::<Vec<_>>();
    split_ciphertext.pop();
    let mut current_character: Vec<bool> = Default::default();
    
    for character in split_ciphertext {
        println!("Attempting to decrypt {}", character);

        current_character.push(decrypt(&private_key, character.to_string()));
        if current_character.len() == 32 {
            println!("bits: {:?}", current_character);
            string_plaintext.push(
                char::from_u32(bits_to_u32(current_character.clone()) as u32)
                    .expect("X")
            );            
            current_character.clear();
        }
    }

    string_plaintext
}

fn encrypt_file(filename: String) -> usize {
    let path_file = Path::new(&filename);
    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path_file) {
        Err(why) => panic!("couldn't open {}: {}", filename, why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut data = String::new();
    let bytes: usize;
    match file.read_to_string(&mut data) {
        Err(why) => panic!("couldn't read {}: {}", filename, why),
        Ok(bytes_) => {
            print!("{} contains:\n{}\n", filename, data);
            bytes = bytes_;
        }
    };

    // Pubkey

    let path = Path::new("public.key");
    let mut file = match File::open(&path) {
        Err(reason) => panic!("Failed opening the public key file:  {}", reason),
        Ok(file) => file,
    };

    let mut pubkey = String::new();
    match file.read_to_string(&mut pubkey) {
        Err(why) => panic!("couldn't read pubkey: {}", why),
        Ok(_) => print!("{} contains:\n{}\n", "Pubkey", pubkey),
    }

    let pubkey_vec: Vec<&str> = pubkey.split("\n")
        .filter(|s| !s.is_empty())  // Filter out empty strings from trailing newlines
        .collect();

    let mut public_key: Mat<f64> = Mat::zeros(N, N+1);

    for (index, equation) in pubkey_vec.iter().enumerate() {
        let mut equation_chars = equation.chars();
        equation_chars.next();        // Remove opening '('
        equation_chars.next_back();   // Remove closing ')'
        let new_equation = equation_chars.as_str();
        let current: Vec<_> = new_equation.split(", ").collect();
        // Now read ALL values including the b value (last column)
        for (index_internal, value) in current.iter().enumerate() {
            public_key[(index, index_internal)] = (*value).parse::<f64>().unwrap();
        }
    }
    let ciphertext = encrypt_text(data, &public_key);
    let mut file = match File::create(path_file) {
        Err(reason) => panic!("{}", reason),
        Ok(file) => file,
    };
    let _ = file.write_all(ciphertext.as_bytes());
    bytes
}

fn decrypt_file(filename: String) -> usize {
    let path_file = Path::new(&filename);
    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file_data = match File::open(&path_file) {
        Err(why) => panic!("couldn't open {}: {}", filename, why),
        Ok(file_data) => file_data,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut data = String::new();
    let bytes: usize;
    match file_data.read_to_string(&mut data) {
        Err(why) => panic!("couldn't read {}: {}", filename, why),
        Ok(bytes_) => {
            print!("{} contains:\n{}\n", filename, data);
            bytes = bytes_;
        }
    };

    // privkey

    let path = Path::new("private.key");
    let mut file = match File::open(&path) {
        Err(reason) => panic!("Failed opening the private key file: {}", reason),
        Ok(file) => file,
    };

    let mut privkey = String::new();
    match file.read_to_string(&mut privkey) {
        Err(why) => panic!("couldn't read privkey: {}", why),
        Ok(_) => print!("{} contains:\n{}\n", "privkey", privkey),
    }

    let mut private_key: Mat<f64> = Mat::zeros(1, N);
    let mut privkeychars = privkey.chars();
    privkeychars.next();
    privkeychars.next_back();
    let privkeyvec: Vec<_> = privkeychars.as_str().split(", ").collect();
    
    for (index, number) in privkeyvec.iter().enumerate() {
        private_key[(0, index)]  = (*number).parse::<f64>().unwrap();
    }
    println!("Data to decrypt is:A\n{}\nA", data);

    let plaintext = decrypt_text(data, &private_key);
    
    let path = Path::new(&filename);
    let mut file = match File::create(&path) {
        Err(reasom) => panic!("{}", reasom),
        Ok(file) => file,
    };
    let _ = file.write_all(plaintext.as_bytes());
    println!("wrote to file: {}", plaintext);
    bytes
}

fn export_keys() {
    let (private_key, public_key) = gen_key();
    for i in 0..private_key.ncols() {
        println!(", {}", private_key[(0, i)]);
    }
    //panic!();
    let path_pub = Path::new("public.key");
    let mut file_pub = match File::create(path_pub) {
        Err(reason) => panic!("{}", reason),
        Ok(file_pub) => file_pub,
    };

    let mut pubkey_string = String::new();

    for row in 0..public_key.nrows() {
        pubkey_string.push_str("(");
        for column in 0..public_key.ncols() {
            let temp = &(public_key[(row, column)].to_string());

            pubkey_string.push_str(temp);
            if column+1 != public_key.ncols() {
                pubkey_string.push_str(", ");
            }
        }
        pubkey_string.push_str(")\n");
    }

    let _ = file_pub.write_all(pubkey_string.as_bytes());


    let path_priv = Path::new("private.key");
    let mut file_priv = match File::create(path_priv) {
        Err(reason) => panic!("{}", reason),
        Ok(file_priv) => file_priv,
    };

    let mut privkey_string = String::from("(");
    
    for column in 0..private_key.ncols() {
        let temp = &(private_key[(0, column)].to_string());
        privkey_string.push_str(temp);
        if column+1 != private_key.ncols() {
            privkey_string.push_str(", ");
        }
    }
    privkey_string.push_str(")");

    let _ = file_priv.write_all(privkey_string.as_bytes());
}

#[allow(dead_code)]
fn main1() {
    export_keys();
    let (private_key, public_key) = gen_key();
    println!("{} rows in the public key", public_key.nrows());
    let ciphertext = encrypt_text("hello, world".to_string(), &public_key);
    println!("A\n{}\nA", ciphertext);
    let plaintext = decrypt_text(ciphertext, &private_key);
    println!("{}", plaintext);
    println!("Welcome! Enter choice:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("input issue");
    println!("{}", input);
    export_keys();
    encrypt_file("plaintext.txt".to_string());
    decrypt_file("plaintext.txt".to_string());
    panic!("shite");
}

fn main() {
    println!("1: encrypt file\n2: decrypt file\n3: generate keys");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("input issue");
    let input = input.trim(); // Remove whitespace including newline
    
    match input {
        "1" => {
            println!("Enter file name:");
            let mut filename = String::new();
            io::stdin().read_line(&mut filename).expect("input issue");
            let filename = filename.trim().to_string(); // Trim filename too!
            let now = Instant::now();
            let bytes = encrypt_file(filename);
            println!("Encrypted {} bytes in {} seconds", bytes, now.elapsed().as_secs_f64());
        },
        "2" => {
            println!("Enter file name:");
            let mut filename = String::new();
            io::stdin().read_line(&mut filename).expect("input issue");
            let filename = filename.trim().to_string();
            let now = Instant::now();
            let bytes = decrypt_file(filename);
            println!("Decrypted {} bytes in {} seconds", bytes, now.elapsed().as_secs_f64());

        },
        "3" => {
            export_keys();
        },
        _ => {
            println!("Invalid option!");
        }
    }
}