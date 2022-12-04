use std::io::Cursor;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

pub struct ZipFileRecord {
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

pub fn read_zip_file_record(data:&[u8]) -> ZipFileRecord {
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

pub fn print_zip_file_record(zfr : &ZipFileRecord) {
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

}