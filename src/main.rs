//use std::fs::File;
//use std::io::Read;
use flate2::write::DeflateDecoder;
use std::io::Write;
use std::thread;
//use crossbeam_utils::thread;
use std::process;
use chrono;
use std::time::Instant;
use std::env;
use lazy_static::lazy_static;

mod crctable;
mod ziputils;

const NUM_THREADS: u8 = 14;

lazy_static! {
    static ref NOW : Instant = Instant::now();
}



fn crc(crc: u32, input: u8) -> u32 {
    return (crc >> 8) ^ crctable::CRCTABLE[((crc & 0xff) as u8 ^ input) as usize];
}

fn update_keys(keys: &mut [u32; 3], c: u8) {
    keys[0] = crc(keys[0], c);
    keys[1] = keys[1].wrapping_add(keys[0] & 0xff);
    // keys[1] = keys[1] * 134775813 + 1;
    keys[1] = keys[1].wrapping_mul(134775813).wrapping_add(1);
    keys[2] = crc(keys[2], (keys[1] >> 24) as u8);
}

fn decrypt_byte(keys: [u32; 3]) -> u8 {
    let temp = keys[2] | 3;
    return ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8;
}



fn try2decrypt(data: &[u8], password: &[u8], crc: u32) -> bool {

    let mut data2 : Vec<u8> = Vec::new();

    // println!("data len: {}", data.len());

    let mut keys: [u32; 3] = [0; 3];
    keys[0] = 0x12345678;
    keys[1] = 0x23456789;
    keys[2] = 0x34567890;

    for i in 0..password.len() {
        update_keys(&mut keys, password[i])
    }

    // The data contains a random 12-byte encryption header
    // Upon decryption, the first 12 bytes need to be discarded.
    // According to the specification, this is done in order to render a plaintext attack on the data ineffective.
    // The specification also states that out of the 12 prepended bytes, only the first 11 are actually random,
    // the last byte is equal to the high order byte of the CRC-32 of the uncompressed contents of the file.
    // This is done to allow the CRC-32 to be checked without having to decompress the file.
    // This gives the ability to quickly verify whether a given password is correct
    // by comparing the last byte of the decrypted 12 byte header to the high order byte of the actual
    // CRC-32 value that is included in the local file header.

    for i in 0..12 {
        let temp = data[i] ^ decrypt_byte(keys);
        update_keys(&mut keys, temp);
        data2.push(temp);
    }

    // println!("data {:?}", &data2[0..11]);


    if data2[11] != (crc >> 24) as u8 {
        // println!("data[11] != (crc >> 24)");
        return false;
    }

    for i in 12..data.len() {
        let temp = data[i] ^ decrypt_byte(keys);
        update_keys(&mut keys, temp);
        data2.push(temp);
    }

    // println!("high order byte {:X?}", data[11]); // FULL CRC: 0xAB8C0EC3, so this print should give 0xAB
    // println!("First deflated byte {:X?}", data[12]);

    let mut deflated: Vec<u8> = Vec::new();
    let mut deflater = DeflateDecoder::new(deflated);
    let result = deflater.write_all(&data2[12..data2.len()]);
    if result.is_err() {
        //println!("deflater.write_all err");
        return false;
    }
    // .unwrap();
    deflated = deflater.finish().unwrap();

    let checksum = crc32fast::hash(&deflated);

    println!("checksum: {:X?}", checksum); // FULL CRC: 0xAB8C0EC3

    return checksum == crc;

}

const VALID_LETTERS: &[u8;62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn get_password_char_array(password : &[u8]) -> Vec<u8> {
    let mut password_chars : Vec<u8> = Vec::new();
    for i in 0..password.len() {
        password_chars.push(VALID_LETTERS[password[i] as usize]);
    }
    return password_chars
}

fn get_password_string(password : &[u8]) -> String {
    return std::str::from_utf8(&get_password_char_array(password)).unwrap().to_string();
}

fn main2(thread_nr: u8, compressed_data: &[u8], crc: u32) {
    let mut counter: u64 = 0;

    for pw_len in 1..9 {
        let mut password : Vec<u8> = Vec::new();
        for _i in 0..pw_len {
            password.push(0);
        }

        loop {
            //println!("password_nrs: {:?}", password);

            if password.last().unwrap() % NUM_THREADS == thread_nr {
                let password_char_array = get_password_char_array(&password);

                let result = try2decrypt(&compressed_data, &password_char_array, crc);
                if result {
                    let password_string = get_password_string(&password);
                    println!("password found: {:?}", password_string);
                    print_current_time();
                    let elapsed = NOW.elapsed();
                    println!("Elapsed: {:.2?}", elapsed);
                    process::exit(0);
                } else {
                    counter += 1;
                    if counter % 100000 == 0 {
                        let password_string = get_password_string(&password);
                        println!("password wrong: {:?} {:?}", password_string, thread_nr);
                    }
                    if get_password_string(&password) == "ENTER" {
                        let password_string = get_password_string(&password);
                        println!("password wrong: {:?} {:?}", password_string, thread_nr);
                    }
                    //let password_string = get_password_string(&password);
                    //println!("password wrong: {:?} {:?}", password_string, thread_nr);
                }
            }
    
            let mut count_letters_at_max = 0;
            let mut pos_of_letter_to_inc=0;
            for i in (0..pw_len).rev() {
                if password[i] == (VALID_LETTERS.len() - 1) as u8 {
                    count_letters_at_max += 1;
                    password[i] = 0;
                } else {
                    pos_of_letter_to_inc = i;
                    break;
                }
            }

            //println!("pos_of_letter_to_inc: {:?}", pos_of_letter_to_inc);
            password[pos_of_letter_to_inc] += 1;
            //println!("password_nrs after inc: {:?}", password);

            if count_letters_at_max == pw_len {
                println!("we have reached the max password for this pw_len");
                break; // we have reached the max password for this pw_len
            }
        }
    }
}

fn print_current_time() {
    let now = chrono::Local::now();
    println!("{}", now.format("%b %-d, %-I:%M:%S").to_string());
}

fn main(){

    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("Usage: ZipMcKracken <zipfile>");
        process::exit(1);
    }

    println!("ZipMcKracken running...");
    print_current_time();
    let elapsed = NOW.elapsed();
    println!("Elapsed: {:.2?}", elapsed); // print once so we get the lazy init.
    
    let data = std::fs::read(&args[1]).unwrap();

    // let s = std::mem::size_of::<ZipFileRecord>();
    // println!("size_of ZipFileRecord: {}", s);
    // wrong due to allignment issue

    let zfr = ziputils::read_zip_file_record( &data );

    ziputils::print_zip_file_record(&zfr);

    let zip_file_record_size = 30;
    let filename_end = zip_file_record_size + zfr.filename_length as usize;
    let filename = &data[zip_file_record_size..filename_end];

    let filename_str = std::str::from_utf8(&filename).unwrap();
    println!("filename: {:?}", filename_str);

    let extra = &data[filename_end..(filename_end + zfr.extra_field_length as usize)];

    let start_of_data = filename_end + zfr.extra_field_length as usize;
    
    println!("extra: {:?}", extra);

    let boxed_data = data.into_boxed_slice();
    let boxed_data_static_ref = Box::leak(boxed_data);

    let compressed_data = &boxed_data_static_ref[start_of_data..start_of_data+zfr.compressed_size as usize];

    
    let handles = (0..NUM_THREADS).map(|thread_nr| {
        println!("HELLO1");
        thread::spawn(move || {
            main2(thread_nr, compressed_data, zfr.crc);
        })
        //println!("HELLO2");
    }).collect::<Vec<_>>();
    
    for h in handles {
        h.join().unwrap();
    }

    /*
    let mut handles = Vec::new();
    for thread_nr in 0..NUM_THREADS {
        println!("HELLO1");

        let res = thread::scope(|s| {
            s.spawn(|_| {
                main2(thread_nr, compressed_data, zfr.crc);
            });
        });
        handles.push(res);
        
        println!("HELLO2");
        
    }

    for thread_nr in 0..NUM_THREADS {
        println!("HELLO3");
        handles[thread_nr as usize].as_ref().unwrap();
        println!("HELLO4");
    }
    */
    
}