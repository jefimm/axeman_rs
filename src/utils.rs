use std::fs::{self, File};
use std::io::Write;

/// Write `content` so readers never see a partial file: data goes to
/// `{file_name}.tmp`, then `rename` replaces the destination atomically.
pub fn write_strings_2_file(content: &str, file_name: &str) -> anyhow::Result<()> {
    let tmp = format!("{file_name}.tmp");
    let write_result = (|| -> anyhow::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, file_name) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("axeman_rs_{label}_{}_{nanos}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn write_leaves_complete_file_and_no_tmp() {
        let path = temp_path("write");
        write_strings_2_file("hello\n", &path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello\n");
        assert!(!fs::metadata(format!("{path}.tmp")).is_ok());

        write_strings_2_file("world\n", &path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "world\n");
        let _ = fs::remove_file(&path);
    }
}
