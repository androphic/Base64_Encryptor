// ============================================================================
// Name        : B64_encryptor.rs
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : Rust implementation of Base64 Encryptor
// ============================================================================
use std::time::SystemTime;

struct B64Encryptor {
    b64_code: [u8; 65],
    b64_index: [u8; 65],
    b_initialized: bool,
}

impl B64Encryptor {
    fn b64_int(&self, ch: u8) -> u8 {
        match ch {
            61 => 64,
            43 => 62,
            47 => 63,
            48..=57 => ch + 4,
            65..=90 => ch - b'A',
            97..=122 => ch - b'a' + 26,
            _ => 64,
        }
    }

    fn rotl16(&self, n: u16, c: u16) -> u16 {
        ((n << c) | (n >> (16 - c))) & 0xFFFF
    }

    fn rotr16(&self, n: u16, c: u16) -> u16 {
        ((n >> c) | (n << (16 - c))) & 0xFFFF
    }

    fn b64_int_from_index(&self, ch: u8) -> u8 {
        if ch == 61 {
            return 64;
        }
        self.b64_index[self.b64_int(ch) as usize]
    }

    fn b64_shuffle(&mut self, i_key: u16) {
        let mut i_dither = 0x5aa5;
        let mut i_key_var = i_key;
        for i in 0..64 {
            i_key_var = self.rotl16(i_key_var, 1);
            i_dither = self.rotr16(i_dither, 1);
            let i_switch_index = i + (i_key_var ^ i_dither) % (64 - i);
            let i_a = self.b64_code[i as usize];
            self.b64_code[i as usize] = self.b64_code[i_switch_index as usize];
            self.b64_code[i_switch_index as usize] = i_a;
        }
        for i in 0..64 {
            self.b64_index[self.b64_int(self.b64_code[i]) as usize] = i as u8;
        }
    }

    fn b64_init(&mut self, i_key: u16) {
        let s_b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for i in 0..64 {
            self.b64_index[i] = i as u8;
            self.b64_code[i] = s_b64_chars.as_bytes()[i];
        }
        self.b64_code[64] = 64;
        self.b64_shuffle(i_key);
        self.b_initialized = true;
    }

    fn b64e_size(&self, in_size: usize) -> usize {
        ((in_size - 1) / 3) * 4 + 4
    }

    fn b64d_size(&self, in_size: usize) -> usize {
        (3 * in_size) / 4
    }

    fn b64_encode(&mut self, input: &[u8], in_len: usize, output: &mut [u8]) -> usize {
        if !self.b_initialized {
            self.b64_init(0);
        }
        let mut i = 0;
        let mut j = 0;
        let mut k = 0;
        let mut s = [0u8; 3];
        let mut i_dither: u16 = 0xa55a;
        let mut i_g = 0;

        while i < in_len {
            i_g = ((input[i] ^ i_dither as u8) & 0xff) as u8;
            s[j] = i_g;
            j += 1;
            i_dither = self.rotr16(i_dither, 1) ^ i_g as u16;
            if j == 3 {
                output[k + 0] = self.b64_code[(s[0] & 0xff) as usize >> 2];
                output[k + 1] = self.b64_code[(((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)) as usize];
                output[k + 2] = self.b64_code[(((s[1] & 0x0F) << 2) | ((s[2] & 0xC0) >> 6)) as usize];
                output[k + 3] = self.b64_code[(s[2] & 0x3F) as usize];
                j = 0;
                k += 4;
            }
            i += 1;
        }
        if j != 0 {
            if j == 1 {
                s[1] = 0;
            }
            output[k + 0] = self.b64_code[(s[0] & 0xff) as usize >> 2];
            output[k + 1] = self.b64_code[(((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)) as usize];
            if j == 2 {
                output[k + 2] = self.b64_code[((s[1] & 0x0F) << 2) as usize];
            } else {
                output[k + 2] = b'=';
            }
            output[k + 3] = b'=';
            k += 4;
        }
        k
    }

    fn b64_decode(&mut self, input: &[u8], in_len: usize, output: &mut [u8]) -> usize {
        if !self.b_initialized {
            self.b64_init(0);
        }

        let mut j = 0;
        let mut k = 0;
        let mut s = [0u8; 4];
        let mut i_dither = 0xa55a;
        let mut i_g = 0;

        for i in 0..in_len {
            s[j] = self.b64_int_from_index(input[i]);
            j += 1;
            if j == 4 {
                if s[1] != 64 {
                    output[k + 0] = ((s[0] & 0xff) << 2 | ((s[1] & 0x30) >> 4)) as u8;
                    if s[2] != 64 {
                        output[k + 1] = (((s[1] & 0x0F) << 4) | ((s[2] & 0x3C) >> 2)) as u8;
                        if s[3] != 64 {
                            output[k + 2] = (((s[2] & 0x03) << 6) | s[3]) as u8;
                            k += 3;
                        } else {
                            k += 2;
                        }
                    } else {
                        k += 1;
                    }
                }
                j = 0;
            }
        }
        let mut i = 0;
        while i < k {
            i_g = output[i];
            output[i] = output[i] ^ i_dither as u8;
            i_dither = self.rotr16(i_dither, 1) ^ i_g as u16;
            i += 1;
        }
        k
    }
}

fn main() {
    let mut i_buffer_de = [0u8; 256];
    let mut i_buffer_en = [0u8; 256 * 4 / 3 + 1];

    println!("B64 encryptor demonstration");
    let i_crypt_key = 128;

    let mut b64_encryptor = B64Encryptor {
        b64_code: [0; 65],
        b64_index: [0; 65],
        b_initialized: false,
    };
    b64_encryptor.b64_init(i_crypt_key);

    println!("Crypt key: 0x{:x}", i_crypt_key);
    println!("B64 code table: {:?}", b64_encryptor.b64_code);
    println!("B64 code table: {}", String::from_utf8_lossy(&b64_encryptor.b64_code[..b64_encryptor.b64_code.len()]));

    let s_test = "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.";
    println!("Plain text: {}", s_test);

    let i_source_size = s_test.len();
    println!("{}", i_source_size);

    for (i, byte) in s_test.bytes().enumerate() {
        i_buffer_de[i] = byte;
    }
    let i_buffer_en_len = b64_encryptor.b64_encode(&i_buffer_de, s_test.len(), &mut i_buffer_en);
    println!("Crypt text: {}", String::from_utf8_lossy(&i_buffer_en[..i_buffer_en_len]));
    println!("{}", i_buffer_en_len);

    let i_buffer_de_len = b64_encryptor.b64_decode(&i_buffer_en[..i_buffer_en_len], i_buffer_en_len, &mut i_buffer_de);
    println!("Decrypt text: {}", String::from_utf8_lossy(&i_buffer_de[..i_buffer_de_len]));
    println!("Decrypt text: {:?}", i_buffer_de);
    println!("{}", i_buffer_de_len);

    let i_ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i32;
    let i_experiments = 1234567;
    let mut i_progress_prev = 0;
    let mut i_progress;
    let mut i_msg_size;

    for i in 0..i_experiments {
        i_buffer_de = [0u8; 256];
        i_buffer_en = [0u8; 256 * 4 / 3 + 1];
        i_msg_size = ((i % 256) as u8) as usize;
        let i_crypt_key = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        b64_encryptor.b64_init(i_crypt_key as u16);
        for i1 in 0..i_msg_size {
            i_buffer_de[i1] = (i1 as u8 | i as u8) as u8;
        }
        let i_buffer_en_len = b64_encryptor.b64_encode(&i_buffer_de[..i_msg_size], i_msg_size, &mut i_buffer_en);
        let i_buffer_de_len = b64_encryptor.b64_decode(&i_buffer_en[..i_buffer_en_len], i_buffer_en_len, &mut i_buffer_de);
        for i1 in 0..i_msg_size {
            assert_eq!(i_buffer_de[i1], (i1 as u8 | i as u8) as u8);
        }
        i_progress = (i * 100 / i_experiments) as i32;
        if i_progress_prev != i_progress {
            println!("Progress: {}%, {}", i_progress, String::from_utf8_lossy(&i_buffer_en[..i_buffer_en_len]).split('\0').next().unwrap());
            i_progress_prev = i_progress;
        }
    }

    println!("Time (seconds): {}", SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i32 - i_ts);
}
