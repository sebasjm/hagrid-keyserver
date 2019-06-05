use failure::Fallible as Result;

use std::path::Path;

use walkdir::WalkDir;
use indicatif::{ProgressBar,ProgressStyle};

use HagridConfig;
use database::{Database,KeyDatabase};
use database::types::Fingerprint;

pub fn do_regenerate(config: &HagridConfig) -> Result<()> {
    let db = KeyDatabase::new_internal(
        config.keys_internal_dir.as_ref().unwrap(),
        config.keys_external_dir.as_ref().unwrap(),
        config.tmp_dir.as_ref().unwrap(),
        false,
    )?;

    let published_dir = config.keys_external_dir.as_ref().unwrap().join("published");
    let dirs: Vec<_> = WalkDir::new(published_dir)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    let progress_bar = ProgressBar::new(dirs.len() as u64);
    progress_bar
        .set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {msg}")
            .progress_chars("##-"));

    for dir in dirs {
        progress_bar.inc(1);
        for dir2 in WalkDir::new(dir)
            .min_depth(1)
            .max_depth(1)
            .into_iter()
            .flatten()
            .map(|entry| entry.into_path()) {

            let prefix2 = dir2.file_name().unwrap().to_string_lossy();
            let prefix1 = dir2.parent().unwrap().file_name().unwrap().to_string_lossy();
            progress_bar.set_message(&format!("Regenerating keys with prefix {}{}",
                                    prefix1, prefix2));
            regenerate_dir(&db, &dir2)?;
        }
    }

    Ok(())
}

fn regenerate_dir(db: &KeyDatabase, dir: &Path) -> Result<()> {
    for path in WalkDir::new(dir)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .flatten()
        .map(|entry| entry.into_path()) {

        let suffix = path.file_name().unwrap().to_string_lossy();
        let prefix2 = path.parent().unwrap().file_name().unwrap().to_string_lossy();
        let prefix1 = path.parent().unwrap().parent().unwrap().file_name().unwrap().to_string_lossy();
        let fpr_str = format!("{}{}{}", prefix1, prefix2, suffix);

        let fpr = fpr_str.parse::<Fingerprint>()?;
        db.regenerate_links(&fpr)?;
    }

    Ok(())
}
