use std::path::{Path, PathBuf};

pub fn find_first_in<T: AsRef<Path>>(path: T, _match: &str) -> std::io::Result<PathBuf> {
    // Read the contents of the directory
    let entries = std::fs::read_dir(path)?;

    for entry in entries {
        let entry = entry?;

        // Get the path of the current entry
        let entry_path = entry.path();

        // Check if the entry is a directory
        if entry_path.is_dir() {
            // If it's a directory, recursively walk through it
            if let Ok(m) = find_first_in(&entry_path, _match) {
                return Ok(m);
            }
        }

        if entry_path.is_file()
            && entry_path
                .file_name()
                .map(|f| f.to_string_lossy())
                .unwrap_or_default()
                .ends_with(_match)
        {
            return Ok(entry_path);
        }
    }

    Err(std::io::ErrorKind::NotFound.into())
}
