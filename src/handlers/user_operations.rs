use std::vec;

use super::secure_operations::password_handling::verify_password;
use super::types::internal_types::{DeviceInformation, NotificationInformation};
use super::types::sendable_types::{
    ExpandedStrippedUserInformation, ProcessedDeviceInformation, StrippedNotificationInformation,
    StrippedUserInformation,
};
use super::{hash_password, rng_alphanumeric, SecureHash, UserInformation, UsernameMap};
use async_recursion::async_recursion;
use dirs::data_dir;
use rocket::tokio::fs::File;
use rocket::tokio::io::{AsyncWriteExt, ErrorKind};
use serde_json;

pub async fn write_user_info_to_file(
    user_info: UserInformation,
    dupe_check: bool,
) -> Result<String, String> {
    let json = match serde_json::to_string(&user_info) {
        Ok(j) => j,
        Err(e) => {
            return Err(format!(
                "Failed to serialize UserInformation to JSON: {}",
                e
            ))
        }
    };

    let dir = data_dir().unwrap();
    let path = dir
        .join("DuckPoweredServer")
        .join("Users")
        .join(user_info.user_id);
    let str_path = path.to_str().unwrap();

    let file_exists = rocket::tokio::fs::metadata(&path).await.is_ok();

    if file_exists && dupe_check {
        return Err(format!("DUPE"));
    }

    let mut file = match File::create(str_path).await {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to create file: {}", e)),
    };

    if let Err(e) = file.write_all(json.as_bytes()).await {
        if e.kind() == ErrorKind::NotFound {
            return Err(format!("Failed to write JSON to file: directory not found"));
        } else {
            return Err(format!("Failed to write JSON to file: {}", e));
        }
    }

    Ok(String::from("UserInformation successfully written to file"))
}

async fn create_friend_code_map(user: UserInformation) -> Result<(), String> {
    let map = UsernameMap {
        owner_id: user.user_id,
    };
    let json = match serde_json::to_string(&map) {
        Ok(j) => j,
        Err(e) => {
            return Err(format!(
                "Failed to serialize UserInformation to JSON: {}",
                e
            ))
        }
    };

    let dir = data_dir().unwrap();
    let path = dir
        .join("DuckPoweredServer")
        .join("FriendCodeMaps")
        .join(user.friend_code);
    let str_path = path.to_str().unwrap();

    let file_exists = rocket::tokio::fs::metadata(&path).await.is_ok();

    if file_exists {
        return Err(format!("DUPE"));
    }

    let mut file = match File::create(str_path).await {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to create file: {}", e)),
    };

    if let Err(e) = file.write_all(json.as_bytes()).await {
        if e.kind() == ErrorKind::NotFound {
            return Err(format!("Failed to write JSON to file: directory not found"));
        } else {
            return Err(format!("Failed to write JSON to file: {}", e));
        }
    }

    Ok(())
}

async fn create_username_map(user: UserInformation) -> Result<(), String> {
    let map = UsernameMap {
        owner_id: user.user_id,
    };
    let json = match serde_json::to_string(&map) {
        Ok(j) => j,
        Err(e) => {
            return Err(format!(
                "Failed to serialize UserInformation to JSON: {}",
                e
            ))
        }
    };

    let dir = data_dir().unwrap();
    let path = dir
        .join("DuckPoweredServer")
        .join("UsernameMaps")
        .join(user.username);
    let str_path = path.to_str().unwrap();

    let file_exists = rocket::tokio::fs::metadata(&path).await.is_ok();

    if file_exists {
        return Err(format!("DUPE"));
    }

    let mut file = match File::create(str_path).await {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to create file: {}", e)),
    };

    if let Err(e) = file.write_all(json.as_bytes()).await {
        if e.kind() == ErrorKind::NotFound {
            return Err(format!("Failed to write JSON to file: directory not found"));
        } else {
            return Err(format!("Failed to write JSON to file: {}", e));
        }
    }

    Ok(())
}

pub async fn test_if_username_meets_requirements(username: &str) -> bool {
    // can only have numbers, uppercase or lowercase letters and underscore
    // must be between 3 and 16 chars
    if username.len() < 3 || username.len() > 16 {
        return false;
    }

    for c in username.chars() {
        if !c.is_alphanumeric() && c != '_' {
            return false;
        }
    }

    true
}

#[async_recursion]
pub async fn create_user(hash: &SecureHash, username: &str) -> Result<(), String> {
    let user_id = rng_alphanumeric(50usize).await;
    let friend_code: String = rng_alphanumeric(6usize).await;
    let new_user_information = UserInformation {
        username: String::from(username),
        pfp: String::from("ducky"),
        friend_code,
        friends: vec![],
        notifications: vec![],
        password_hashed: hash.hash.clone(),
        salt: hash.salt.clone(),
        user_id,
        devices: vec![],
        secret: rng_alphanumeric(50usize).await,
    };

    match create_username_map(new_user_information.clone()).await {
        Ok(()) => match create_friend_code_map(new_user_information.clone()).await {
            Ok(_) => match write_user_info_to_file(new_user_information, true).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if e == format!("DUPE") {
                        return create_user(hash, username).await;
                    } else {
                        return Err(e);
                    }
                }
            },
            Err(e) => {
                if e == format!("DUPE") {
                    return create_user(hash, username).await;
                } else {
                    return Err(e);
                }
            }
        },
        Err(e) => {
            if e == format!("DUPE") {
                return Err(String::from("DUPLICATE_USERNAME"));
            } else {
                return Err(e);
            }
        }
    }
}

use crate::rocket::tokio::io::AsyncReadExt;

pub async fn get_user_info_from_username(username: &str) -> Result<UserInformation, String> {
    let user_id = get_user_id_from_username(username).await?;

    return get_user_info_from_id(user_id.as_str()).await;
}

pub async fn get_user_info_from_id(id: &str) -> Result<UserInformation, String> {
    let dir = data_dir().unwrap();
    let file_path = dir.join("DuckPoweredServer").join("Users").join(id);

    let mut file = File::open(file_path).await.map_err(|e| format!("{}", e))?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .await
        .map_err(|e| format!("{}", e))?;

    let user_info: UserInformation =
        serde_json::from_str(&contents).map_err(|e| format!("{}", e))?;

    Ok(user_info)
}

pub async fn get_user_info_from_id_no_ps_increment(id: &str) -> Result<UserInformation, String> {
    let dir = data_dir().unwrap();
    let file_path = dir.join("DuckPoweredServer").join("Users").join(id);
    let mut file = File::open(file_path).await.map_err(|e| format!("{}", e))?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .await
        .map_err(|e| format!("{}", e))?;

    let user_info: UserInformation =
        serde_json::from_str(&contents).map_err(|e| format!("{}", e))?;

    Ok(user_info)
}

async fn get_user_id_from_username(username: &str) -> Result<String, String> {
    let dir = data_dir().unwrap();
    let file_path = dir
        .join("DuckPoweredServer")
        .join("UsernameMaps")
        .join(username);
    let mut file = File::open(file_path).await.map_err(|_| format!("404"))?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .await
        .map_err(|e| format!("{}", e))?;

    let json: UsernameMap = serde_json::from_str(&contents).map_err(|e| format!("{}", e))?;

    // if we make it here, everything is OK
    return Ok(json.owner_id.to_string());
}

pub async fn get_user_id_from_friend_code(code: &str) -> Result<String, String> {
    let dir = data_dir().unwrap();
    let path = dir
        .join("DuckPoweredServer")
        .join("FriendCodeMaps")
        .join(code);
    let mut file = File::open(path).await.map_err(|_| format!("404"))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .await
        .map_err(|e| format!("{}", e))?;

    let json: UsernameMap = serde_json::from_str(&contents).map_err(|e| format!("{}", e))?;

    // if we make it here, everything is OK
    return Ok(json.owner_id.to_string());
}

pub async fn actually_change_password(user_id: &str, new_password: &str) -> Result<(), String> {
    let user_info = match get_user_info_from_id(user_id).await {
        Ok(info) => info,
        Err(e) => return Err(format!("{}", e)),
    };

    let new_hash = hash_password(new_password).await;

    let updated_user_info = UserInformation {
        username: user_info.username.clone(),
        pfp: user_info.pfp.clone(),
        friend_code: user_info.friend_code.clone(),
        friends: user_info.friends.clone(),
        password_hashed: new_hash.hash.clone(),
        notifications: user_info.notifications.clone(),
        salt: new_hash.salt.clone(),
        user_id: user_id.to_string(),
        devices: user_info.devices.clone(),
        secret: rng_alphanumeric(50usize).await,
    };

    match write_user_info_to_file(updated_user_info, false).await {
        Ok(_) => return Ok(()),
        Err(e) => return Err(format!("{}", e)),
    }
}

use crate::handlers::types::internal_types::DateReportingInfo as date_reporting_info;
use chrono::{Datelike, Local};
use rocket::tokio::{fs, io};

use chrono::Weekday;
use chrono::{Duration, NaiveDate};

async fn get_current_dd_mm_yyyy() -> String {
    let local_date = Local::now().date_naive();
    format!(
        "{:02}-{:02}-{}",
        local_date.day(),
        local_date.month(),
        local_date.year()
    )
}

async fn get_most_recent_monday() -> String {
    let local_date = Local::now().date_naive();
    let weekday = local_date.weekday();
    let days_to_subtract = match weekday {
        Weekday::Mon => 0,
        Weekday::Tue => 1,
        Weekday::Wed => 2,
        Weekday::Thu => 3,
        Weekday::Fri => 4,
        Weekday::Sat => 5,
        Weekday::Sun => 6,
    };

    let most_recent_monday = local_date - Duration::days(days_to_subtract.into());

    format!(
        "{:02}-{:02}-{}",
        most_recent_monday.day(),
        most_recent_monday.month(),
        most_recent_monday.year()
    )
}

async fn get_next_monday() -> String {
    let local_date = Local::now().date_naive();
    let weekday = local_date.weekday();
    let days_to_add = match weekday {
        Weekday::Mon => 7,
        Weekday::Tue => 6,
        Weekday::Wed => 5,
        Weekday::Thu => 4,
        Weekday::Fri => 3,
        Weekday::Sat => 2,
        Weekday::Sun => 1,
    };

    let next_monday = local_date + Duration::days(days_to_add.into());

    format!(
        "{:02}-{:02}-{}",
        next_monday.day(),
        next_monday.month(),
        next_monday.year()
    )
}

async fn read_or_create_file(folder_name: &str) -> Result<(date_reporting_info, String), String> {
    let formatted_date = get_current_dd_mm_yyyy().await;
    let dir = data_dir().unwrap();
    let file_path = dir
        .join("DuckPoweredServer")
        .join("DailyReporting")
        .join(folder_name)
        .join(formatted_date);

    let contents: Result<String, String> = match fs::read_to_string(&file_path).await {
        Ok(contents) => Ok(contents),
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                let data = date_reporting_info { times: 0 };
                let serialized_data = match serde_json::to_string(&data) {
                    Ok(serialized_data) => serialized_data,
                    Err(e) => return Err(format!("Error serializing data: {}", e)),
                };
                match fs::write(&file_path, &serialized_data).await {
                    Ok(_) => return Ok((data, String::from(file_path.to_string_lossy()))),
                    Err(e) => Err(format!("Error creating file: {}", e)),
                }
            } else {
                Err(format!("Error reading file: {}", e))
            }
        }
    };
    let safe_contents = match contents {
        Ok(value) => value,
        Err(e) => return Err(e),
    };
    let data = match serde_json::from_str(&safe_contents) {
        Ok(data) => data,
        Err(e) => return Err(format!("Error deserializing data: {}", e)),
    };
    Ok((data, String::from(file_path.to_string_lossy())))
}

pub async fn increment_times(folder_name: &str) -> Result<(), String> {
    let mut data = match read_or_create_file(folder_name).await {
        Ok(data) => data,
        Err(e) => return Err(format!("Error reading or creating file: {}", e)),
    };
    data.0.times += 1;
    let serialized_data = match serde_json::to_string(&data.0) {
        Ok(serialized_data) => serialized_data,
        Err(e) => return Err(format!("Error serializing data: {}", e)),
    };
    match fs::write(&data.1, &serialized_data).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Error writing to file: {}", e)),
    }
}

pub async fn delete_user(user_info: UserInformation, password: String) -> Result<String, String> {
    match verify_password(
        password.as_str(),
        user_info.salt.as_str(),
        user_info.password_hashed.as_str(),
    )
    .await
    {
        true => {
            let dir = data_dir().unwrap();
            let path = dir
                .join("DuckPoweredServer")
                .join("Users")
                .join(user_info.user_id);
            let str_path = path.to_str().unwrap();

            let metadata = match rocket::tokio::fs::metadata(&path).await {
                Ok(m) => m,
                Err(e) => return Err(format!("Failed to get file metadata: {}", e)),
            };

            if metadata.is_file() {
                match rocket::tokio::fs::remove_file(str_path).await {
                    Ok(_) => {
                        let dir = data_dir().unwrap();
                        let friend_code_path = dir
                            .join("DuckPoweredServer")
                            .join("FriendCodeMaps")
                            .join(user_info.friend_code);

                        if let Err(e) = rocket::tokio::fs::remove_file(friend_code_path).await {
                            return Err(format!("Failed to delete friend code file: {}", e));
                        }

                        let username_path = dir
                            .join("DuckPoweredServer")
                            .join("UsernameMaps")
                            .join(user_info.username);
                        if let Err(e) = rocket::tokio::fs::remove_file(username_path).await {
                            return Err(format!("Failed to delete username file: {}", e));
                        }

                        Ok(String::from("User account successfully deleted"))
                    }
                    Err(e) => return Err(format!("Failed to delete user file: {}", e)),
                }
            } else {
                Err(format!("Path does not point to a file"))
            }
        }
        false => Err(format!("WRONG PASSWORD")),
    }
}

async fn convert_devices(
    devices: Vec<DeviceInformation>,
) -> Result<Vec<ProcessedDeviceInformation>, String> {
    let mut return_vec: Vec<ProcessedDeviceInformation> = vec![];
    for d in devices {
        let mut labels_vec: Vec<String> = vec![];
        let mut values_vec: Vec<u8> = vec![];
        // prder the ps_data by the value.0
        // value.0 is a date in yyyy-mm-dd format, order from earliest to latest
        // if two values of value.0 fall on the same date, order by the label in this order: M, Tu, W, Th, F, Sa, Su, <anything else>
        let mut ordered_ps_data: Vec<(&String, &(Vec<u8>, String))> = d.ps_data.iter().collect();
        ordered_ps_data.sort_by(|a, b| {
            let a_date = NaiveDate::parse_from_str(a.1.1.as_str(), "%d-%m-%Y").unwrap();
            let b_date = NaiveDate::parse_from_str(b.1.1.as_str(), "%d-%m-%Y").unwrap();
            if a_date < b_date {
                return std::cmp::Ordering::Less;
            } else if a_date > b_date {
                return std::cmp::Ordering::Greater;
            } else {
                let a_label = a.0;
                let b_label = b.0;
                let a_order = match a_label.as_str() {
                    "M" => 0,
                    "Tu" => 1,
                    "W" => 2,
                    "Th" => 3,
                    "F" => 4,
                    "Sa" => 5,
                    "Su" => 6,
                    _ => 7,
                };
                let b_order = match b_label.as_str() {
                    "M" => 0,
                    "Tu" => 1,
                    "W" => 2,
                    "Th" => 3,
                    "F" => 4,
                    "Sa" => 5,
                    "Su" => 6,
                    _ => 7,
                };
                if a_order < b_order {
                    return std::cmp::Ordering::Less;
                } else if a_order > b_order {
                    return std::cmp::Ordering::Greater;
                } else {
                    return std::cmp::Ordering::Equal;
                }
            }
        });
        for (label, value) in ordered_ps_data {
            let value = &value.0;
            // get the average of the values
            let mut sum = 0;
            for v in value {
                sum += v;
            }
            let average = sum / value.len() as u8;
            // round down to the nearest 1
            let rounded = average - (average % 1);
            labels_vec.push(label.to_string());
            values_vec.push(rounded);
        }
        return_vec.push(ProcessedDeviceInformation {
            device_name: d.device_name,
            device_id: d.device_id,
            line_graph_labels: labels_vec,
            line_graph_values: values_vec,
        });
    }
    return Ok(return_vec);
}

async fn convert_notifcations(
    notifications: Vec<NotificationInformation>,
) -> Result<Vec<StrippedNotificationInformation>, String> {
    let mut return_vec: Vec<StrippedNotificationInformation> = vec![];
    for n in notifications {
        let pfp = match get_user_info_from_id(n.from_user_id.as_str()).await {
            Ok(p) => p.pfp,
            Err(_) => format!("fallback"), // user account probably deleted, let's use the fallback picture
        };

        // if the notification's remove_by is passed, remove it from the list

        let remove_by = match NaiveDate::parse_from_str(n.remove_by.as_str(), "%d-%m-%Y") {
            Ok(date) => date,
            Err(_) => return Err(format!("DATE HANDLING ERROR 3")),
        };

        let current_date =
            match NaiveDate::parse_from_str(get_current_dd_mm_yyyy().await.as_str(), "%d-%m-%Y") {
                Ok(date) => date,
                Err(_) => return Err(format!("DATE HANDLING ERROR 4")),
            };

        if current_date > remove_by {
            continue;
        }

        return_vec.push(StrippedNotificationInformation {
            read: n.read,
            title: n.title,
            info: n.info,
            pfp,
            uid: n.uid,
        });
    }
    return Ok(return_vec);
}

async fn find_avg_power_saving_of_device(device_info: DeviceInformation) -> usize {
    let mut sum = 0usize;
    let mut count = 0usize;
    for (_, (values, _)) in device_info.ps_data.iter() {
        for v in values {
            sum += *v as usize;
            count += 1;
        }
    }
    let average = sum / count;
    average
}

async fn find_avg_power_saving_of_entire_user(user_info: UserInformation) -> usize {
    let mut sum = 0usize;
    let mut count = 0usize;
    for d in user_info.devices {
        let device_avg = find_avg_power_saving_of_device(d).await;
        sum += device_avg;
        count += 1;
    }
    let average = sum / count;
    average
}

pub async fn generate_notification(user_info: UserInformation) -> Result<UserInformation, String> {
    let mut user_info = user_info.clone();
    // Notification Types:
    // 1. Feature Highlight (i.e. "Have you tried adding friends?")
    // 2. Device Highlight (i.e. "Your device 'School Laptop' has saved on average 20% power with DuckPowered. Keep it up!")
    // 3. Friend Highlight (i.e. "Your friend 'John' has saved on average 20% power with DuckPowered. Keep it up!")

    // gen a random number between 1 and 3 to figure out the type
    let notification_type = rand::random::<u8>() % 3 + 1;
    match notification_type {
        1 => {
            // Feature Highlight
            // Features that can be highlighted:
            // Feature #1: Adding Friends
            //             Title: "The more the merrier!"
            //             Body: "Invite your friends to DuckPowered and save power together with in-app collaboration!"
            // Feature #2: Getting DuckPowered on more devices
            //             Title: "DuckPowered Everywhere!"
            //             Body: "Get DuckPowered on all your devices to save power whereever you go!"
            // Feature #3: Using in-app graphs to track power usage
            //             Title: "Graphs Galore!"
            //             Body: "Use DuckPowered's in-app graphs to track your power usage over time and gain poweful insights!"

            let feature_index = rand::random::<u8>() % 3 + 1;

            let notification = match feature_index {
                1 => NotificationInformation {
                    read: false,
                    title: String::from("The more the merrier! 🌟"),
                    info: String::from(
                        "Invite your friends to DuckPowered and save power together with in-app collaboration!",
                    ),
                    from_user_id: String::from("DuckPowered"),
                    remove_by: get_next_monday().await,
                    uid: rng_alphanumeric(10usize).await,
                },
                2 => NotificationInformation {
                    read: false,
                    title: String::from("DuckPowered Everywhere! 🌍"),
                    info: String::from(
                        "Get DuckPowered on all your devices to save power whereever you go!",
                    ),
                    from_user_id: String::from("DuckPowered"),
                    remove_by: get_next_monday().await,
                    uid: rng_alphanumeric(10usize).await,
                },
                3 => NotificationInformation {
                    read: false,
                    title: String::from("Graphs Galore! 📊"),
                    info: String::from(
                        "Use DuckPowered's in-app graphs to track your power usage over time and gain poweful insights!",
                    ),
                    from_user_id: String::from("DuckPowered"),
                    remove_by: get_next_monday().await,
                    uid: rng_alphanumeric(10usize).await,
                },
                _ => return Err(String::from("The feature index was out of bounds.")),
            };

            user_info.notifications.push(notification);
        }
        2 => {
            // Device Highlight
            let device_index = rand::random::<usize>() % user_info.devices.len();
            let device = &user_info.devices[device_index];
            let notification = NotificationInformation {
                read: false,
                title: String::from("Device Highlight 💻"),
                info: format!(
                    "On the device '{}', you've reduced your power consumption by {}% with DuckPowered. Keep it up!",
                    device.clone().device_name,
                    find_avg_power_saving_of_device(device.clone()).await
                ),
                from_user_id: String::from("DuckPowered"),
                remove_by: get_next_monday().await,
                uid: rng_alphanumeric(10usize).await,
            };
            user_info.notifications.push(notification);
        }
        3 => {
            // Friend Highlight

            if user_info.friends.len() == 0 {
                let notification = NotificationInformation {
                    read: false,
                    title: String::from("Save power together! 🌟"),
                    info: String::from("Have you tried adding friends to DuckPowered?"),
                    from_user_id: String::from("DuckPowered"),
                    remove_by: get_next_monday().await,
                    uid: rng_alphanumeric(10usize).await,
                };
                user_info.notifications.push(notification);
                return Ok(user_info);
            }

            let friend_index = rand::random::<usize>() % user_info.friends.len();
            let friend_info = match get_user_info_from_id(user_info.friends[friend_index].owner_id.as_str()).await {
                Ok(info) => info,
                Err(_) => {
                    let notification = NotificationInformation {
                        read: false,
                        title: String::from("Save power together! 🌟"),
                        info: String::from("Friends don't let friends waste power! Invite your friends to DuckPowered today!"),
                        from_user_id: String::from("DuckPowered"),
                        remove_by: get_next_monday().await,
                        uid: rng_alphanumeric(10usize).await,
                    };
                    user_info.notifications.push(notification);
                    return Ok(user_info);
                }
            };
            
            let notification = NotificationInformation {
                read: false,
                title: String::from("Friend Highlight ✨"),
                info: format!(
                    "Your friend '{}' has saved on average {}% power with DuckPowered. Let them know how well they're doing!",
                    friend_info.clone().username,
                    find_avg_power_saving_of_entire_user(friend_info.clone()).await
                ),
                from_user_id: friend_info.user_id,
                remove_by: get_next_monday().await,
                uid: rng_alphanumeric(10usize).await,
            };
            user_info.notifications.push(notification);
        }
        _ => return Err(String::from("The notification type was out of bounds.")),
    }
    return Ok(user_info);
}

pub async fn collate_user_information_public(
    user_id: String,
) -> Result<ExpandedStrippedUserInformation, String> {
    match get_user_info_from_id(user_id.as_str()).await {
        Ok(_) => {
            match get_user_info_from_id(user_id.as_str()).await {
                Ok(info) => {
                    let mut friends_vec: Vec<StrippedUserInformation> = vec![];
                    for f in info.friends {
                        let friend_info = match get_user_info_from_id(f.owner_id.as_str()).await {
                            Ok(info) => info,
                            Err(e) => return Err(e),
                        };
                        friends_vec.push(StrippedUserInformation {
                            username: friend_info.username,
                            pfp: friend_info.pfp,
                            friend_code: friend_info.friend_code,
                            devices: match convert_devices(friend_info.devices).await {
                                Ok(d) => d,
                                Err(e) => return Err(e),
                            },
                        })
                    }
                    // iterate through each notification
                    Ok(ExpandedStrippedUserInformation {
                        username: info.username,
                        friends: friends_vec,
                        friend_code: info.friend_code,
                        devices: match convert_devices(info.devices).await {
                            Ok(d) => d,
                            Err(e) => return Err(e),
                        },
                        pfp: info.pfp,
                        notifications: match convert_notifcations(info.notifications).await {
                            Ok(n) => n,
                            Err(e) => return Err(e),
                        },
                    })
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

pub async fn remove_friend(user_info: UserInformation, friend_code: &str) -> Result<(), String> {
    let mut toy_info = user_info.clone();
    let friend_id = match get_user_id_from_friend_code(friend_code).await {
        Ok(id) => id,
        Err(e) => return Err(e.to_string()),
    };

    // Find the index of the friend in the user's friend list
    let friend_index = user_info
        .friends
        .iter()
        .position(|f| f.owner_id == friend_id)
        .ok_or_else(|| format!("404"))?;

    // Remove the friend from the user's friend list
    toy_info.friends.remove(friend_index);

    write_user_info_to_file(toy_info.clone(), false).await?;

    // Remove the user from the friend's friend list
    let friend_info = match get_user_info_from_id(friend_id.as_str()).await {
        Ok(info) => info,
        Err(e) => return Err(e),
    };

    let user_id = toy_info.user_id.clone();
    let user_index = friend_info
        .friends
        .iter()
        .position(|f| f.owner_id == user_id)
        .ok_or_else(|| format!("404"))?;

    let mut friend_info = friend_info.clone();
    friend_info.friends.remove(user_index);

    write_user_info_to_file(friend_info.clone(), false).await?;
    
    Ok(())
}

pub async fn alter_notification_read_status(
    user_info: UserInformation,
    notification_id: String,
    read_status: bool,
) -> Result<(), String> {
    let mut toy_info = user_info.clone();
    // Find the index of the notification in the user's notification list
    let notification_index = user_info
        .notifications
        .iter()
        .position(|n| n.uid == notification_id);

    match notification_index {
        Some(index) => {
            // Mark the notification as read
            toy_info.notifications[index].read = read_status;

            // Write the updated user info to file
            write_user_info_to_file(toy_info, false).await?;

            Ok(())
        }
        None => return Err("404".to_string()),
    }
}

pub async fn insert_into_device_ps_data(
    info: UserInformation,
    device_id: String,
    day: String,
    value_to_insert: u8,
) -> Result<(), String> {
    let mut toy_info = info.clone();

    // find the index of the device in the user's device list
    let device_index = info.devices.iter().position(|d| d.device_id == device_id);

    match device_index {
        Some(index) => {
            let most_recent_monday = get_most_recent_monday().await;
            // see if the day is already in the device's ps_data
            let day_index = toy_info.devices[index].ps_data.get(&day);
            match day_index {
                Some(_) => {
                    // see if the recorded most recent monday is the same as the current most recent monday
                    if toy_info.devices[index].ps_data.get(&day).unwrap().1 != most_recent_monday {
                        // if it's not, we need to reset the day's data
                        toy_info.devices[index].ps_data.get_mut(&day).unwrap().0 =
                            vec![value_to_insert];
                        toy_info.devices[index].ps_data.get_mut(&day).unwrap().1 =
                            most_recent_monday;
                        write_user_info_to_file(toy_info, false).await?;
                        return Ok(());
                    }
                    // insert the value into the day's data
                    toy_info.devices[index]
                        .ps_data
                        .get_mut(&day)
                        .unwrap()
                        .0
                        .push(value_to_insert);
                    toy_info.devices[index].ps_data.get_mut(&day).unwrap().1 =
                        get_most_recent_monday().await;
                    write_user_info_to_file(toy_info, false).await?;
                    Ok(())
                }
                None => {
                    // create a new day in the device's ps_data
                    toy_info.devices[index].ps_data.insert(
                        day.clone(),
                        (vec![value_to_insert], get_most_recent_monday().await),
                    );
                    write_user_info_to_file(toy_info, false).await?;
                    Ok(())
                }
            }
        }
        None => return Err("404".to_string()),
    }
}

pub async fn change_username(
    user_info: UserInformation,
    proposed_new_username: String,
) -> Result<(), String> {
    if !test_if_username_meets_requirements(proposed_new_username.as_str()).await {
        return Err(format!("USERNAME_REQUIREMENTS_NOT_MET"));
    }

    let mut toy_info = user_info.clone();
    let old_username = toy_info.username.clone();
    toy_info.username = proposed_new_username.clone();

    // write the new username to the UsernameMaps folder
    match create_username_map(toy_info.clone()).await {
        Ok(_) => {
            // remove the old username from the UsernameMaps folder
            let dir = data_dir().unwrap();
            let old_username_path = dir
                .join("DuckPoweredServer")
                .join("UsernameMaps")
                .join(old_username);
            if let Err(e) = rocket::tokio::fs::remove_file(old_username_path).await {
                return Err(format!("Failed to remove old username file: {}", e));
            }

            // write the updated user info to file
            write_user_info_to_file(toy_info, false).await?;

            Ok(())
        }
        Err(e) => {
            if e == format!("DUPE") {
                return Err(format!("DUPLICATE_USERNAME"));
            } else {
                return Err(e);
            }
        }
    }
}
