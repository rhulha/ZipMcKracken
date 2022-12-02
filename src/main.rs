use std::fs;
//use std::fs::File;
//use std::io::Read;
use flate2::write::DeflateDecoder;
use std::io::Write;

mod crctable;

fn crc(crc: u32, input: u8) -> u32 {
    return (crc >> 8) ^ crctable::CRCTABLE[((crc & 0xff) as u8 ^ input) as usize];
}

fn update_keys(keys: &mut [u32; 3], c: u8) {
    keys[0] = crc(keys[0], c);
    keys[1] = keys[1] + (keys[0] & 0xff);
    // keys[1] = keys[1] * 134775813 + 1;
    keys[1] = keys[1].wrapping_mul(134775813) + 1;
    keys[2] = crc(keys[2], (keys[1] >> 24) as u8);
}

fn decrypt_byte(keys: [u32; 3]) -> u8 {
    let temp = keys[2] | 3;
    return ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8;
}

fn main() {
    println!("ZipMcKracken running...");

    let password = b"ENTER";

    let mut keys: [u32; 3] = [0; 3];
    keys[0] = 0x12345678;
    keys[1] = 0x23456789;
    keys[2] = 0x34567890;

    for i in 0..password.len() {
        update_keys(&mut keys, password[i])
    }

    // encrypted_data.bin is the secret, encrypted and compressed key.jpg PAYLOAD ONLY WITHOUT ANY STANDARD ZIP HEADERS found inside Mx.png

    let mut data = std::fs::read("encrypted_data.bin").unwrap();

    // 12-byte encryption header
    // Upon decryption, the first 12 bytes need to be discarded.
    // According to the specification, this is done in order to render a plaintext attack on the data ineffective.
    // The specification also states that out of the 12 prepended bytes, only the first 11 are actually random,
    // the last byte is equal to the high order byte of the CRC-32 of the uncompressed contents of the file.
    // This is done to allow the CRC-32 to be checked without having to decompress the file.
    // This gives the ability to quickly verify whether a given password is correct
    // by comparing the last byte of the decrypted 12 byte header to the high order byte of the actual
    // CRC-32 value that is included in the local file header.

    for i in 0..data.len() {
        let temp = data[i] ^ decrypt_byte(keys);
        update_keys(&mut keys, temp);
        data[i] = temp;
    }

    println!("high order byte {:X?}", data[11]); // FULL CRC: 0xAB8C0EC3, so this print should give 0xAB

    let path = std::path::Path::new("unencrypted.zip");
    let mut file = match fs::File::create(path) {
        Err(why) => panic!("couldn't open file: {}", why),
        Ok(file) => file,
    };

    let zip_header = std::fs::read("zip_header.bin").unwrap();
    file.write_all(&zip_header).expect("Unable to write file");

    file.write_all(&data[12..data.len()])
        .expect("Unable to write file");

    println!("data len: {}", data.len());

    let zip_footer = std::fs::read("zip_footer.bin").unwrap();
    file.write_all(&zip_footer).expect("Unable to write file");


    println!("First deflated byte {:X?}", data[12]);

    let mut deflated: Vec<u8> = Vec::new();
    let mut deflater = DeflateDecoder::new(deflated);
    deflater.write_all(&data[12..data.len()]).unwrap();
    deflated = deflater.finish().unwrap();

    let checksum = crc32fast::hash(&deflated);

    println!("checksum: {:X?}", checksum); // FULL CRC: 0xAB8C0EC3

    //fs::write("unencrypted.bin", &data[12..data.len()]).expect("Unable to write file");
}
