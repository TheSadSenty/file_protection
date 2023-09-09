use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use std::env::args;
use std::fs::{read, read_dir, OpenOptions};
use std::io::Write;
use std::os::unix::prelude::OpenOptionsExt;
use std::path::Path;
extern "C" {
    fn geteuid() -> u32;
}
enum PasswordMode {
    CreatePassword,
    UpdatePassword,
}
fn create_or_update_password(mode: PasswordMode, config_path: &Path) -> Result<(), ()> {
    match mode {
        PasswordMode::CreatePassword => match prompt_password("Please enter the password: ") {
            Ok(pass) => {
                let config = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .mode(0o600)
                    .create(true)
                    .open(config_path);
                match config {
                    Ok(mut file) => {
                        let mut hasher = Sha256::new();
                        hasher.update(pass.as_bytes());
                        let mut hash = format!("{:x}", hasher.finalize());
                        hash.push('\n');
                        match file.write(hash.as_bytes()) {
                            Ok(_) => {}
                            Err(_) => {
                                println!("Error while writing to template.tbl");
                                return Err(());
                            }
                        };
                    }
                    Err(error) => {
                        println!("Error while creating template.tbl. {}", error);
                        return Err(());
                    }
                }
                return Ok(());
            }
            Err(_) => {
                return Err(());
            }
        },
        PasswordMode::UpdatePassword => {
            let config = OpenOptions::new().write(true).read(true).open(config_path);
            match config {
                Ok(mut file) => {
                    match prompt_password("Please enter your previous password: ") {
                        Ok(pass_to_check) => match read(config_path) {
                            Ok(file_text) => {
                                let mut hasher = Sha256::new();
                                hasher.update(pass_to_check.as_bytes());
                                let pass_to_check_hashed = format!("{:x}", hasher.finalize());
                                let file_text_string = String::from_utf8(file_text).unwrap();
                                //get sha256 hash
                                let existing_password = &file_text_string[0..=63];
                                if existing_password == pass_to_check_hashed {
                                    let new_pass =
                                        prompt_password("Please enter your new password: ")
                                            .unwrap();
                                    let mut new_pass_hasher = Sha256::new();
                                    new_pass_hasher.update(new_pass.as_bytes());
                                    let mut new_pass_hashed =
                                        format!("{:x}", new_pass_hasher.finalize());
                                    new_pass_hashed.push_str(&file_text_string[64..]);
                                    match file.set_len(0) {
                                        Ok(_) => {}
                                        Err(_) => {
                                            return Err(());
                                        }
                                    }
                                    match file.write(new_pass_hashed.as_bytes()) {
                                        Ok(_) => {
                                            return Ok(());
                                        }
                                        Err(_) => {
                                            println!("Error while updating the password");
                                            return Err(());
                                        }
                                    }
                                } else {
                                    println!("Wrong password!");
                                    return Err(());
                                }
                            }
                            Err(_) => {
                                return Err(());
                            }
                        },
                        Err(_) => {
                            return Err(());
                        }
                    }
                }
                Err(error) => {
                    println!("Error while opening template.tbl. {}", error);
                    return Err(());
                }
            }
        }
    }
}
fn find_files(file_list: Vec<String>) {
    todo!()
}
fn main() -> Result<(), ()> {
    let uid: u32 = unsafe { geteuid() };
    let mut is_config = false;
    let file_list = Vec::<String>::new();
    if uid != 0 {
        println!("You must be a root user to run this program.");
        //return Err(());
    }
    let config = Path::new("./template.tbl");
    match config.try_exists() {
        Ok(existence) => {
            if existence {
                is_config = true;
                println!("Found template.tbl");
            } else {
                let mode = PasswordMode::CreatePassword;
                println!("Creating template.tbl");
                create_or_update_password(mode, config)?;
                println!("Successfully updated password");
            }
        }
        Err(_) => {
            println!("Can't check existence of template.tbl");
            return Err(());
        }
    }
    let argv = args().nth(1);
    match argv {
        Some(sec_arg) => {
            let arg_str = sec_arg.as_str();
            match arg_str {
                "-h" => {
                    todo!()
                }
                "--help" => {
                    todo!()
                }
                "passwd" => {
                    if is_config {
                        let mode = PasswordMode::UpdatePassword;
                        create_or_update_password(mode, config)?;
                    }
                }
                _ => {
                    println!("Wrong arg");
                }
            }
        }
        None => {}
    }
    let dir = read_dir(".").expect("Failed to open dir");
    for files in dir {
        println!("{}", files.as_ref().unwrap().path().display(),);
        if files.as_ref().unwrap().file_type().unwrap().is_file() {}
    }
    Ok(())
}
