use std::fs::File;
use std::io::Write;

pub fn write_strings_2_file(content: &str, file_name: &str) {
    File::create(file_name)
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();
}
