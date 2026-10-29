//! Prints a JSON array with the ntfs2refs file-content digest (XXH3-128) of
//! each file argument, in argument order, or null where a file cannot be read.
//! For lab scripts that compare converted files with conversion records; the
//! output holds no paths, so console code pages cannot alter it. Read only.
fn main() {
    use std::io::Read;
    let digests: Vec<serde_json::Value> = std::env::args_os()
        .skip(1)
        .map(|path| {
            let digest = (|| -> std::io::Result<String> {
                let mut file = std::fs::File::open(&path)?;
                let mut hash = n2r_win32::content_digest::Hasher::new();
                let mut buffer = vec![0u8; 1024 * 1024];
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 {
                        return Ok(hash.finish());
                    }
                    hash.update(&buffer[..count]);
                }
            })();
            digest.map_or(serde_json::Value::Null, serde_json::Value::String)
        })
        .collect();
    println!("{}", serde_json::Value::Array(digests));
}
