use regex::Regex;
use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use std::env::args;
use std::fs::{read, read_dir, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::prelude::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
extern "C" {
    fn geteuid() -> u32;
}
enum PasswordMode {
    CreatePassword,
    UpdatePassword,
}
enum FileProtection {
    TurnOn,
    TurnOff,
}
fn create_or_update_password(mode: PasswordMode, config_path: &Path) {
    match mode {
        PasswordMode::CreatePassword => {
            let pass = prompt_password("Please enter the password: ").expect("Can't read password");
            let mut config = OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o600)
                .open(config_path)
                .expect("Error while creating template.tbl.");
            let mut hasher = Sha256::new();
            hasher.update(pass.as_bytes());
            let mut hash = format!("{:x}", hasher.finalize());
            hash.push('\n');
            config
                .write(hash.as_bytes())
                .expect("Error while writing to template.tbl");
            Command::new("chattr")
                .arg("+i")
                .arg(config_path)
                .output()
                .expect(
                    format!(
                        "Error while changing attributes of {}",
                        config_path.display()
                    )
                    .as_str(),
                );
        }
        PasswordMode::UpdatePassword => {
            let pass_to_check = prompt_password("Please enter your previous password: ")
                .expect("Can't read password");
            match check_pass(config_path, &pass_to_check) {
                Ok(_) => {
                    Command::new("chattr")
                        .arg("-i")
                        .arg(config_path)
                        .output()
                        .expect(
                            format!(
                                "Error while changing attributes of {}",
                                config_path.display()
                            )
                            .as_str(),
                        );
                    let mut config = File::open(config_path).expect("Can't open template.tbl");
                    let mut file_text_string = String::new();
                    config
                        .read_to_string(&mut file_text_string)
                        .expect("Can't read template.tbl");
                    config = OpenOptions::new()
                        .write(true)
                        .read(true)
                        .truncate(true)
                        .open(config_path)
                        .expect("Can't open template.tbl");
                    let new_pass = prompt_password("Please enter your new password: ")
                        .expect("Can't read password");
                    let mut new_pass_hasher = Sha256::new();
                    new_pass_hasher.update(new_pass.as_bytes());
                    let mut new_pass_hashed = format!("{:x}", new_pass_hasher.finalize());
                    new_pass_hashed.push_str(&file_text_string[64..]);
                    config
                        .write(new_pass_hashed.as_bytes())
                        .expect("Error while updating the password");
                    Command::new("chattr")
                        .arg("+i")
                        .arg(config_path)
                        .output()
                        .expect(
                            format!(
                                "Error while changing attributes of {}",
                                config_path.display()
                            )
                            .as_str(),
                        );
                }
                Err(_) => {}
            }
        }
    }
}
fn turn_on_or_off(config_path: &Path, mode: FileProtection) {
    let mut regexp_list = Vec::<Regex>::new();
    let file = read(config_path).expect("Can't read template.tbl");
    let file_text_string = String::from_utf8(file).expect("Invalid unicode in template.tbl");
    let file_lines = file_text_string.lines();
    for (index, line) in file_lines.enumerate() {
        if index == 0 {
            continue;
        }
        regexp_list.push(Regex::new(line).expect("Found an invalid regular expression"));
    }
    let dir = read_dir(".").expect("Failed to open dir");
    let pass = prompt_password("Please enter your password: ").expect("Password entry failed");
    match check_pass(config_path, &pass) {
        Ok(_) => {
            for files in dir {
                for regexp in &regexp_list {
                    let file_name = files.as_ref().unwrap().file_name();
                    let pattern = file_name
                        .as_os_str()
                        .to_str()
                        .expect("The file name contains invalid Unicode");
                    match regexp.captures(pattern) {
                        Some(_) => match mode {
                            FileProtection::TurnOn => {
                                Command::new("chown")
                                    .arg("root")
                                    .arg(files.as_ref().unwrap().file_name())
                                    .output()
                                    .expect(
                                        format!(
                                            "Error while changing owner of {}",
                                            files.as_ref().unwrap().path().display()
                                        )
                                        .as_str(),
                                    );
                                Command::new("chmod")
                                    .arg("700")
                                    .arg(files.as_ref().unwrap().file_name())
                                    .output()
                                    .expect(
                                        format!(
                                            "Error while changing mode of {}",
                                            files.as_ref().unwrap().path().display()
                                        )
                                        .as_str(),
                                    );
                                Command::new("chattr")
                                    .arg("+i")
                                    .arg(files.as_ref().unwrap().file_name())
                                    .output()
                                    .expect(
                                        format!(
                                            "Error while changing attributes of {}",
                                            files.as_ref().unwrap().path().display()
                                        )
                                        .as_str(),
                                    );
                            }
                            FileProtection::TurnOff => {
                                Command::new("chattr")
                                    .arg("-i")
                                    .arg(files.as_ref().unwrap().file_name())
                                    .output()
                                    .expect(
                                        format!(
                                            "Error while changing attributes of {}",
                                            files.as_ref().unwrap().path().display()
                                        )
                                        .as_str(),
                                    );
                                Command::new("chmod")
                                    .arg("777")
                                    .arg(files.as_ref().unwrap().file_name())
                                    .output()
                                    .expect(
                                        format!(
                                            "Error while changing mode of {}",
                                            files.as_ref().unwrap().path().display()
                                        )
                                        .as_str(),
                                    );
                            }
                        },
                        None => {
                            //skiping
                        }
                    }
                }
            }
        }
        Err(_) => {}
    }
}
fn check_pass(config_path: &Path, pass_to_check: &str) -> Result<(), ()> {
    let file_text_utf8 = read(config_path).expect("Can't read template.tbl");
    let file_text_string =
        String::from_utf8(file_text_utf8).expect("Invalid unicode in template.tbl");
    let current_password = file_text_string
        .lines()
        .nth(0)
        .expect("Missing password at first line");
    let mut hasher = Sha256::new();
    hasher.update(pass_to_check.as_bytes());
    let pass_to_check_hashed = format!("{:x}", hasher.finalize());
    let current_password_string = String::from(current_password);
    if pass_to_check_hashed == current_password_string {
        return Ok(());
    } else {
        println!("Wrong password!");
        return Err(());
    }
}
fn add_regexp_to_file(config_path: &Path, regexp: &str) {
    Command::new("chattr")
        .arg("-i")
        .arg(config_path)
        .output()
        .expect(
            format!(
                "Error while changing attributes of {}",
                config_path.display()
            )
            .as_str(),
        );
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(config_path)
        .expect("Error while opening template.tbl");
    file.write(regexp.as_bytes())
        .expect("Error while writing template.tb");
    Command::new("chattr")
        .arg("+i")
        .arg(config_path)
        .output()
        .expect(
            format!(
                "Error while changing attributes of {}",
                config_path.display()
            )
            .as_str(),
        );
}
fn main() -> Result<(), ()> {
    let uid: u32 = unsafe { geteuid() };
    let mut is_config = false;
    if uid != 0 {
        println!("You must be a root user to run this program.");
        return Err(());
    }
    let config = Path::new("./template.tbl");
    match config.try_exists() {
        Ok(existence) => {
            if existence {
                is_config = true;
            } else {
                let mode = PasswordMode::CreatePassword;
                create_or_update_password(mode, config);
                return Ok(());
            }
        }
        Err(_) => {
            println!("Can't check existence of template.tbl");
            return Err(());
        }
    }
    match args().nth(1) {
        Some(first_arg) => match first_arg.as_str() {
            "-h" => {
                todo!()
            }
            "--help" => {
                todo!()
            }
            "passwd" => {
                if is_config {
                    let mode = PasswordMode::UpdatePassword;
                    create_or_update_password(mode, config);
                }
            }
            "add" => match args().nth(2) {
                Some(mut regexp_pattern) => {
                    match Regex::new(&regexp_pattern) {
                        Ok(_) => {
                            regexp_pattern.push('\n');
                            add_regexp_to_file(config, &regexp_pattern);
                        }
                        Err(_) => {
                            println!("Error while parsing a regular expression");
                            return Err(());
                        }
                    };
                }
                None => {
                    println!("Missing regexp patern");
                    return Err(());
                }
            },
            "on" => {
                let mode = FileProtection::TurnOn;
                turn_on_or_off(config, mode);
            }
            "off" => {
                let mode = FileProtection::TurnOff;
                turn_on_or_off(config, mode);
            }
            _ => {
                println!("Wrong arg");
            }
        },
        None => {}
    }
    Ok(())
}
