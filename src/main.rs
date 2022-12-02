//use std::fs::File;
//use std::io::Read;
use flate2::write::DeflateDecoder;
use std::io::Write;
use std::io::Cursor;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

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

struct ZipFileRecord {
    pub signature: u32,
    pub version: u16,
    pub flags: u16,
    pub compression: u16,
    pub time: u16,
    pub date: u16,
    pub c3c: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub filename_length: u16,
    pub extra_field_length: u16,
    //pub filename: [u8; ZipFileRecord::filename_length],
}

fn read_zip_file_record(data:&[u8]) -> ZipFileRecord {
    let mut zfr = ZipFileRecord {
        signature: 0,
        version: 0,
        flags: 0,
        compression: 0,
        time: 0,
        date: 0,
        c3c: 0,
        compressed_size: 0,
        uncompressed_size: 0,
        filename_length: 0,
        extra_field_length: 0,
    };

    let mut cursor = Cursor::new(data);

    zfr.signature = cursor.read_u32::<BigEndian>().unwrap();
    zfr.version = cursor.read_u16::<LittleEndian>().unwrap();
    zfr.flags = cursor.read_u16::<LittleEndian>().unwrap();
    zfr.compression = cursor.read_u16::<LittleEndian>().unwrap();
    zfr.time = cursor.read_u16::<LittleEndian>().unwrap();
    zfr.date = cursor.read_u16::<LittleEndian>().unwrap();
    zfr.c3c = cursor.read_u32::<LittleEndian>().unwrap();
    zfr.compressed_size = cursor.read_u32::<LittleEndian>().unwrap();
    zfr.uncompressed_size = cursor.read_u32::<LittleEndian>().unwrap();
    zfr.filename_length = cursor.read_u16::<LittleEndian>().unwrap();
    zfr.extra_field_length = cursor.read_u16::<LittleEndian>().unwrap();

    
    return zfr;
}

fn try2decrypt(data: & mut[u8], password: &[u8], crc: u32) -> bool {

    println!("data len: {}", data.len());

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

    for i in 0..data.len() {
        let temp = data[i] ^ decrypt_byte(keys);
        update_keys(&mut keys, temp);
        data[i] = temp;
    }

    println!("high order byte {:X?}", data[11]); // FULL CRC: 0xAB8C0EC3, so this print should give 0xAB

    if data[11] != (crc >> 24) as u8 {
        return false;
    }

    println!("First deflated byte {:X?}", data[12]);

    let mut deflated: Vec<u8> = Vec::new();
    let mut deflater = DeflateDecoder::new(deflated);
    deflater.write_all(&data[12..data.len()]).unwrap();
    deflated = deflater.finish().unwrap();

    let checksum = crc32fast::hash(&deflated);

    println!("checksum: {:X?}", checksum); // FULL CRC: 0xAB8C0EC3

    return checksum == crc;

}

fn main() {
    println!("ZipMcKracken running...");

    let mut data = std::fs::read("test.zip").unwrap();

    // let s = std::mem::size_of::<ZipFileRecord>();
    // println!("size_of ZipFileRecord: {}", s);
    // wrong due to allignment issue

    let zfr = read_zip_file_record( &data );

    println!("signature: {:X?}", zfr.signature);
    println!("version: {:?}", zfr.version);
    println!("flags: {:X?}", zfr.flags);
    println!("compression: {:X?}", zfr.compression);
    println!("time: {:X?}", zfr.time); // winstructs::timestamp::DosTime
    println!("date: {:X?}", zfr.date);
    println!("c3c: {:X?}", zfr.c3c);
    println!("compressed_size: {:?}", zfr.compressed_size);
    println!("uncompressed_size: {:?}", zfr.uncompressed_size);
    println!("filename_length: {:?}", zfr.filename_length);
    println!("extra_field_length: {:?}", zfr.extra_field_length);

    let zip_file_record_size = 30;
    let filename_end = zip_file_record_size + zfr.filename_length as usize;
    let filename = &data[zip_file_record_size..filename_end];

    println!("filename: {:?}", filename);

    let extra = &data[filename_end..(filename_end + zfr.extra_field_length as usize)];

    let start_of_data = filename_end + zfr.extra_field_length as usize;
    
    println!("extra: {:?}", extra);

    let valid_letters = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    for pw_len in 1..9 {
        let mut password : Vec<u8> = Vec::new();
        let mut password_counter : Vec<u8> = Vec::new();
        for _j in 0..pw_len {
            password_counter.push(0);
        }
        for _j in 0..pw_len {
            password.push(valid_letters[0]);
        }
        loop {
            println!("password_counter: {:?}", password_counter);

            for j in 0..pw_len {
                password[j] = valid_letters[password_counter[j] as usize];
            }
            println!("password: {:?}", std::str::from_utf8(&password).unwrap());


            let mut counter = 0;
            let mut pos=0;
            for i in (0..pw_len).rev() {
                if password_counter[i] == (valid_letters.len() - 1) as u8 {
                    counter += 1;
                } else {
                    pos = i;
                    break;
                }
            }

            println!("pos: {:?}", pos);

            password_counter[pos] += 1;

            println!("password_counter after inc: {:?}", password_counter);

            if password_counter[pos] == valid_letters.len() as u8 {
                println!("overflow");
                if pos > 0 {
                    password_counter[pos-1] += 1;
                }
                password_counter[pos] = 0;
                println!("password_counter after overflow: {:?}", password_counter);
            }

            if counter == pw_len {
                println!("we have reached the max password for this pw_len");
                break; // we have reached the max password for this pw_len
            }
        }
        if 4>5{
            let result = try2decrypt(& mut data[start_of_data..start_of_data+zfr.compressed_size as usize], &password, zfr.c3c);
            if result {
                println!("password: {:?}", password);
                return;
            } else {
                println!("password: {:?}", password);
            }
            println!("result: {:?}", result);
        }
    }

}
