use std::fs::File;
use std::io::Write;


pub fn write_strings_2_file(strings: &[String], file_name: &str) {
    let mut output = File::create(file_name).unwrap();

    for s in strings {
        output.write(s.as_bytes()).unwrap();
        output.write("\n".as_bytes()).unwrap();
    }
}