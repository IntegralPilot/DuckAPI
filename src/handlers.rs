use std::collections::HashMap;
use std::str::FromStr;

use rocket::http::Status;
use rocket::response::{content, status};
use rocket::serde::json::Json;

mod request_guards;
use request_guards::header_filtering::agent_information::DuckPoweredAgentInformation;

mod context;
use context::context::DUCKPOWERED_CONTEXT;

mod types;
use types::internal_types::{UserInformation, UsernameMap};
use types::recieveable_types::{ChangePasswordProps, LoginProps};

mod secure_operations;
use secure_operations::{
    password_handling::{hash_password, SecureHash},
    rng_alphanumeric,
};

mod user_operations;
use user_operations::create_user;

use self::request_guards::header_filtering::agent_information::DuckPoweredAuthInfo;
use self::secure_operations::password_handling::{
    change_password, test_if_password_meets_requirements, verify_password,
};

use self::secure_operations::tokens::{
    create_token, DuckPoweredAuthClaim, DuckPoweredTokenScope, DuckPoweredTokenScopes,
    DuckPoweredTokenType,
};

use self::types::internal_types::DeviceInformation;
use self::types::recieveable_types::DeleteAccountProps;
use self::types::sendable_types::GenericAPIResponse;
use self::user_operations::{
    alter_notification_read_status, change_username, collate_user_information_public, delete_user, generate_notification, get_user_id_from_friend_code, get_user_info_from_username, insert_into_device_ps_data, remove_friend, test_if_username_meets_requirements, write_user_info_to_file
};
use crate::handlers::types::recieveable_types::CreateAccountProps;
use crate::handlers::user_operations::{get_user_info_from_id, increment_times};

macro_rules! generate_response {
    ($status:expr, $response:expr) => {
        return status::Custom(
            $status,
            rocket::response::content::RawJson($response.to_string()),
        )
    };
}

#[get("/updateStatus")]
pub async fn update_status_route(
    agent_info: DuckPoweredAgentInformation,
) -> status::Custom<content::RawJson<String>> {
    let version = agent_info.version;
    if version == 0 {
        generate_response!(
            Status::BadRequest,
            GenericAPIResponse {
                message: "Invalid User-Agent".to_string(),
                error: true,
            }
        );
    } else if version < DUCKPOWERED_CONTEXT.last_security_update_versioncode {
        generate_response!(
            Status::UpgradeRequired,
            GenericAPIResponse {
                message: "Update Required".to_string(),
                error: true,
            }
        );
    } else if version < DUCKPOWERED_CONTEXT.last_update_versioncode {
        generate_response!(
            Status::UpgradeRequired,
            GenericAPIResponse {
                message: "Update Recommended".to_string(),
                error: false,
            }
        );
    } else {
        generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Up to date".to_string(),
                error: false,
            }
        );
    }
}

#[get("/ping")]
pub async fn ping_route() -> status::Custom<content::RawJson<String>> {
    generate_response!(
        Status::Ok,
        GenericAPIResponse {
            message: "Pong".to_string(),
            error: false,
        }
    );
}

#[post("/auth/createAccount", format = "json", data = "<props>")]
pub async fn create_account_route(
    props: Json<CreateAccountProps>,
    _agent_info: DuckPoweredAgentInformation,
) -> status::Custom<content::RawJson<String>> {
    let password = props.password.as_str();
    if !test_if_password_meets_requirements(password).await {
        generate_response!(
            Status::BadRequest,
            GenericAPIResponse {
                message: "The password does not meet the requirements. You must use at least 8 characters, including uppercase and lowercase letters, digits, and special characters.".to_string(),
                error: true,
            }
        );
    }
    if !test_if_username_meets_requirements(props.username.as_str()).await {
        generate_response!(
            Status::BadRequest,
            GenericAPIResponse {
                message: "The username does not meet the requirements. You must use between 3 and 16 alphanumeric characters, including an underscore.".to_string(),
                error: true,
            }
        );
    }
    let secure_hash = hash_password(password).await;
    let username_freed = props.username.as_str();
    match create_user(&secure_hash, username_freed).await {
        Ok(()) => generate_response!(
            Status::Created,
            GenericAPIResponse {
                message: "Account created successfully.".to_string(),
                error: false,
            }
        ),
        Err(e) => {
            if e == String::from("DUPLICATE_USERNAME") {
                generate_response!(
                    Status::Conflict,
                    GenericAPIResponse {
                        message: "Username already in use.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {}", e),
                        error: true,
                    }
                );
            }
        }
    }
}

#[post("/auth/login", format = "json", data = "<props>")]
pub async fn login_route(props: Json<LoginProps>) -> status::Custom<content::RawJson<String>> {
    let user_information = match get_user_info_from_username(props.username.as_str()).await {
        Ok(info) => info,
        Err(e) => {
            if e == format!("404") {
                generate_response!(
                    Status::NotFound,
                    GenericAPIResponse {
                        message: "There isn't a DuckID account with that username.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    };
    // check that the password is correct
    match verify_password(
        props.password.as_str(),
        user_information.salt.as_str(),
        user_information.password_hashed.as_str(),
    )
    .await
    {
        true => {
            // 1 year from now, in mills since unix epoch
            let expiry: u64 = (chrono::Utc::now() + chrono::Duration::days(365))
                .timestamp_millis()
                .try_into()
                .unwrap();
            let mut scopes = vec![];
            for scope in props.requested_scopes.iter() {
                scopes.push(DuckPoweredTokenScope::from_str(scope.as_str()).unwrap());
            }
            let scopes = DuckPoweredTokenScopes(scopes);
            let token = DuckPoweredAuthClaim {
                token_type: DuckPoweredTokenType::Refresh,
                for_uid: user_information.user_id,
                scopes: scopes,
                user_secret: user_information.secret,
                valid_until: expiry,
            };
            match create_token(token) {
                Ok(t) => generate_response!(
                    Status::Ok,
                    GenericAPIResponse {
                        message: t,
                        error: false,
                    }
                ),
                Err(e) => generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                ),
            }
        }
        false => generate_response!(
            Status::Unauthorized,
            GenericAPIResponse {
                message: "The password is incorrect.".to_string(),
                error: true,
            }
        ),
    }
}

#[post("/auth/refresh")]
pub async fn refresh_route(auth: DuckPoweredAuthInfo) -> status::Custom<content::RawJson<String>> {
    if auth.claim.token_type != DuckPoweredTokenType::Refresh {
        generate_response!(
            Status::BadRequest,
            GenericAPIResponse {
                message: "Invalid token type.".to_string(),
                error: true,
            }
        );
    }
    // 7 days from now
    let expiry: u64 = (chrono::Utc::now() + chrono::Duration::days(7))
        .timestamp_millis()
        .try_into()
        .unwrap();
    let token = DuckPoweredAuthClaim {
        token_type: DuckPoweredTokenType::Access,
        for_uid: auth.claim.for_uid,
        scopes: auth.claim.scopes,
        user_secret: auth.claim.user_secret,
        valid_until: expiry,
    };
    match create_token(token) {
        Ok(t) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: t,
                error: false,
            }
        ),
        Err(e) => generate_response!(
            Status::InternalServerError,
            GenericAPIResponse {
                message: format!("Internal Server Error: {:?}", e),
                error: true,
            }
        ),
    }
}

#[post("/auth/changePassword", format = "json", data = "<props>")]
pub async fn change_password_route(
    props: Json<ChangePasswordProps>,
) -> status::Custom<content::RawJson<String>> {
    let user_information = match get_user_info_from_username(props.username.as_str()).await {
        Ok(info) => info,
        Err(e) => {
            if e == format!("404") {
                generate_response!(
                    Status::NotFound,
                    GenericAPIResponse {
                        message: "There isn't a DuckID account with that username.".to_string(),
                        error: true,
                    }
                );
            } else if e == format!("The existing password is incorrect.") {
                generate_response!(
                    Status::Unauthorized,
                    GenericAPIResponse {
                        message: "The existing password is incorrect.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    };
    match change_password(
        props.old_password.as_str(),
        user_information.salt.as_str(),
        user_information.password_hashed.as_str(),
        user_information.user_id.as_str(),
        props.new_password.as_str(),
    )
    .await
    {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Password changed.".to_string(),
                error: false,
            }
        ),
        Err(e) => {
            if e == format!("WRONG PASSWORD") {
                generate_response!(
                    Status::Unauthorized,
                    GenericAPIResponse {
                        message: "The old password is incorrect.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    }
}

#[put("/device/byname/<name>")]
pub async fn create_device_route(
    name: String,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::DevicesWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    // see if the user already has a device with that name
    for device in auth.user_info.devices.iter() {
        if device.device_name == name {
            generate_response!(
                Status::Conflict,
                GenericAPIResponse {
                    message: "A device with that name already exists.".to_string(),
                    error: true,
                }
            );
        }
    }
    let info = auth.user_info;
    let mut new_info = info.clone();
    let device_id = rng_alphanumeric(16).await;
    new_info.devices.push(DeviceInformation {
        device_id: device_id.clone(),
        device_name: name,
        ps_data: HashMap::new(),
    });
    match write_user_info_to_file(new_info, false).await {
        Ok(_) => generate_response!(
            Status::Created,
            GenericAPIResponse {
                message: device_id,
                error: false,
            }
        ),
        Err(e) => generate_response!(
            Status::InternalServerError,
            GenericAPIResponse {
                message: format!("Internal Server Error: {:?}", e),
                error: true,
            }
        ),
    }
}

#[put("/device/<id>/name/<newname>")]
pub async fn update_device_name_route(
    id: String,
    newname: String,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::DevicesWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    let info = auth.user_info;
    let mut new_info = info.clone();
    let mut found = false;
    for device in new_info.devices.iter_mut() {
        if device.device_id == id {
            device.device_name = newname.clone();
            found = true;
            break;
        }
    }
    if !found {
        generate_response!(
            Status::NotFound,
            GenericAPIResponse {
                message: "Device not found.".to_string(),
                error: true,
            }
        );
    }
    // check if there are now duplicate device names
    for device in new_info.devices.iter() {
        let mut count = 0;
        for other_device in new_info.devices.iter() {
            if device.device_name == other_device.device_name {
                count += 1;
            }
        }
        if count > 1 {
            generate_response!(
                Status::Conflict,
                GenericAPIResponse {
                    message: "A device with that name already exists.".to_string(),
                    error: true,
                }
            );
        }
    }
    match write_user_info_to_file(new_info, false).await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Device name updated.".to_string(),
                error: false,
            }
        ),
        Err(e) => generate_response!(
            Status::InternalServerError,
            GenericAPIResponse {
                message: format!("Internal Server Error: {:?}", e),
                error: true,
            }
        ),
    }
}

#[put("/device/<id>/byday/<day>/<value>")]
pub async fn update_device_ps_route(
    id: String,
    day: String,
    value: u8,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::DevicesWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    match insert_into_device_ps_data(auth.user_info, id, day, value).await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Device updated.".to_string(),
                error: false,
            }
        ),
        Err(e) => {
            if e == format!("404") {
                generate_response!(
                    Status::NotFound,
                    GenericAPIResponse {
                        message: "Device not found.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    }
}
#[delete("/device/<device_id>")]
pub async fn destroy_device_route(
    device_id: String,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::DevicesWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    let info = auth.user_info;
    // see if the user has a device with that id
    let mut found = false;
    for device in info.devices.iter() {
        if device.device_id == device_id {
            found = true;
            break;
        }
    }
    if !found {
        generate_response!(
            Status::NotFound,
            GenericAPIResponse {
                message: "Device not found.".to_string(),
                error: true,
            }
        );
    }
    let mut new_info = info.clone();
    new_info.devices.retain(|d| d.device_id != device_id);
    match write_user_info_to_file(new_info, false).await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Device removed.".to_string(),
                error: false,
            }
        ),
        Err(e) => generate_response!(
            Status::InternalServerError,
            GenericAPIResponse {
                message: format!("Internal Server Error: {:?}", e),
                error: true,
            }
        ),
    }
}

#[put("/stats/numberOfDAUForeground")]
pub async fn increment_number_of_dau_foreground() -> status::Custom<content::RawJson<String>> {
    match increment_times("DAU-Foreground").await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "DONE".to_string(),
                error: false,
            }
        ),
        Err(e) => generate_response!(
            Status::InternalServerError,
            GenericAPIResponse {
                message: format!("{}", e),
                error: true,
            }
        ),
    }
}

#[put("/stats/numberOfDAUBackground")]
pub async fn increment_number_of_dau_background() -> status::Custom<content::RawJson<String>> {
    match increment_times("DAU-Background").await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "DONE".to_string(),
                error: false,
            }
        ),
        Err(e) => generate_response!(
            Status::InternalServerError,
            GenericAPIResponse {
                message: format!("{}", e),
                error: true,
            }
        ),
    }
}

#[delete("/userInfo/self", format = "json", data = "<props>")]
pub async fn destroy_account_route(
    props: Json<DeleteAccountProps>,
) -> status::Custom<content::RawJson<String>> {
    let user_information = match get_user_info_from_username(props.username.as_str()).await {
        Ok(info) => info,
        Err(e) => {
            if e == format!("404") {
                generate_response!(
                    Status::NotFound,
                    GenericAPIResponse {
                        message: "There isn't a DuckID account with that username.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    };

    match verify_password(
        props.password.as_str(),
        user_information.salt.as_str(),
        user_information.password_hashed.as_str(),
    )
    .await
    {
        false => generate_response!(
            Status::Unauthorized,
            GenericAPIResponse {
                message: "The password is incorrect.".to_string(),
                error: true,
            }
        ),
        true => {}
    }

    match delete_user(user_information, props.password.clone()).await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Account deleted.".to_string(),
                error: false,
            }
        ),
        Err(e) => {
            if e == format!("WRONG PASSWORD") {
                generate_response!(
                    Status::Unauthorized,
                    GenericAPIResponse {
                        message: "The password is incorrect.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    }
}

#[get("/userInfo/self")]
pub async fn user_information_collator_route(
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    match collate_user_information_public(auth.claim.for_uid).await {
        Ok(i) => {
            let mut new_i = i.clone();
            // redact any info that shouldn't be sent to the client, based on the claimed scopes
            if !auth
                .claim
                .scopes
                .0
                .contains(&DuckPoweredTokenScope::FriendsReadFullContent)
            {
                if auth
                    .claim
                    .scopes
                    .0
                    .contains(&DuckPoweredTokenScope::FriendsReadNames)
                {
                    // remove all data from each friend, except for the username and pfp
                    for friend in new_i.friends.iter_mut() {
                        friend.friend_code = String::new();
                        friend.devices = vec![];
                    }
                } else {
                    new_i.friends = vec![];
                }
            }
            if !auth
                .claim
                .scopes
                .0
                .contains(&DuckPoweredTokenScope::NotificationsRead)
            {
                new_i.notifications = vec![];
            }
            if !auth
                .claim
                .scopes
                .0
                .contains(&DuckPoweredTokenScope::DevicesRead)
            {
                new_i.devices = vec![];
            }
            if !auth
                .claim
                .scopes
                .0
                .contains(&DuckPoweredTokenScope::CoreUserInfoRead)
            {
                new_i.username = String::new();
                new_i.friend_code = String::new();
                new_i.pfp = String::new();
            }
            generate_response!(
                Status::Ok,
                GenericAPIResponse {
                    message: serde_json::to_string(&new_i).unwrap(),
                    error: false,
                }
            );
        }
        Err(e) => generate_response!(
            Status::InternalServerError,
            GenericAPIResponse {
                message: format!("Internal Server Error: {:?}", e),
                error: true,
            }
        ),
    }
}

#[put("/userInfo/self/username/<newname>")]
pub async fn update_username_route(
    newname: String,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::CoreUserInfoWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    match change_username(auth.user_info, newname).await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Username updated.".to_string(),
                error: false,
            }
        ),
        Err(e) => {
            if e == format!("DUPLICATE_USERNAME") {
                generate_response!(
                    Status::Conflict,
                    GenericAPIResponse {
                        message: "Username already in use.".to_string(),
                        error: true,
                    }
                );
            } else if e == format!("USERNAME_REQUIREMENTS_NOT_MET") {
                generate_response!(
                    Status::BadRequest,
                    GenericAPIResponse {
                        message: "The username does not meet the requirements. You must use between 3 and 16 alphanumeric characters, including an underscore.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    }
}

#[put("/userInfo/self/pfp/<newpfp>")]
pub async fn update_pfp_route(
    newpfp: String,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::CoreUserInfoWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    let mut new_info = auth.user_info.clone();
    new_info.pfp = newpfp.clone();
    match write_user_info_to_file(new_info, false).await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Profile picture updated.".to_string(),
                error: false,
            }
        ),
        Err(e) => generate_response!(
            Status::InternalServerError,
            GenericAPIResponse {
                message: format!("Internal Server Error: {:?}", e),
                error: true,
            }
        ),
    }
}

#[put("/friend/<code>")]
pub async fn friend_adder_route(
    code: String,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::FriendsWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    if code == auth.user_info.friend_code {
        generate_response!(
            Status::BadRequest,
            GenericAPIResponse {
                message: "You can't add yourself as a friend.".to_string(),
                error: true,
            }
        );
    }
    // see if the user already has a friend with that code
    for friend in auth.user_info.friends.iter() {
       match get_user_info_from_id(friend.owner_id.as_str()).await {
           Ok(friend_info) => {
               if friend_info.friend_code == code {
                   generate_response!(
                       Status::Conflict,
                       GenericAPIResponse {
                           message: "You already have that friend.".to_string(),
                           error: true,
                       }
                   );
               }
           },
           Err(_) => {}
       }
    }
    match get_user_id_from_friend_code(code.as_str()).await {
        Ok(friends_id) => {
            let mut edited_user_info = auth.user_info.clone();
            edited_user_info.friends.push(UsernameMap {
                owner_id: friends_id.clone(),
            });
            match write_user_info_to_file(edited_user_info, false).await {
                Ok(_) => {
                    // now add yourself to the other user's friends
                    let friends_id_clone = friends_id.clone();
                    match get_user_info_from_id(friends_id_clone.as_str()).await {
                        Ok(mut other_user_info) => {
                            other_user_info.friends.push(UsernameMap {
                                owner_id: auth.user_info.user_id.clone(),
                            });
                            match write_user_info_to_file(other_user_info, false).await {
                                Ok(_) => generate_response!(
                                    Status::Ok,
                                    GenericAPIResponse {
                                        message: "Friend added.".to_string(),
                                        error: false,
                                    }
                                ),
                                Err(e) => generate_response!(
                                    Status::InternalServerError,
                                    GenericAPIResponse {
                                        message: format!("Internal Server Error: {:?}", e),
                                        error: true,
                                    }
                                ),
                            }
                        }
                        Err(e) => generate_response!(
                            Status::InternalServerError,
                            GenericAPIResponse {
                                message: format!("Internal Server Error: {:?}", e),
                                error: true,
                            }
                        ),
                    }
                }
                Err(e) => generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                ),
            }
        }
        Err(e) => match e.as_str() {
            "404" => {
                generate_response!(
                    Status::NotFound,
                    GenericAPIResponse {
                        message: "Friend not found.".to_string(),
                        error: true,
                    }
                );
            }
            _ => {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        },
    }
}

#[delete("/friend/<code>")]
pub async fn friend_remover_route(
    code: String,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::FriendsWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    match remove_friend(auth.user_info, code.as_str()).await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Friend removed.".to_string(),
                error: false,
            }
        ),
        Err(e) => {
            if e == format!("404") {
                generate_response!(
                    Status::NotFound,
                    GenericAPIResponse {
                        message: "Friend not found.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    }
}

#[get("/notification/new")]
pub async fn new_notification_route(
    auth: DuckPoweredAuthInfo
) -> status::Custom<content::RawJson<String>> {
    if !auth.claim.scopes.0.contains(&DuckPoweredTokenScope::NotificationsWrite) {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }

    match generate_notification(auth.user_info).await {
        Ok(new_info) => {
            match write_user_info_to_file(new_info, false).await {
                Ok(_) => generate_response!(
                    Status::Ok,
                    GenericAPIResponse {
                        message: "Notification generated.".to_string(),
                        error: false,
                    }
                ),
                Err(e) => generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                ),
            }
        },
        Err(e) => {
            generate_response!(
                Status::InternalServerError,
                GenericAPIResponse {
                    message: format!("Internal Server Error: {:?}", e),
                    error: true,
                }
            )
        }
    }
}

#[put("/notification/<code>/readStatus/<read>")]
pub async fn notifcation_read_marker_route(
    code: String,
    read: bool,
    auth: DuckPoweredAuthInfo,
) -> status::Custom<content::RawJson<String>> {
    if !auth
        .claim
        .scopes
        .0
        .contains(&DuckPoweredTokenScope::NotificationsWrite)
    {
        generate_response!(
            Status::Forbidden,
            GenericAPIResponse {
                message: "Insufficient permissions.".to_string(),
                error: true,
            }
        );
    }
    match alter_notification_read_status(auth.user_info, code, read).await {
        Ok(_) => generate_response!(
            Status::Ok,
            GenericAPIResponse {
                message: "Notification read status updated.".to_string(),
                error: false,
            }
        ),
        Err(e) => {
            if e == format!("404") {
                generate_response!(
                    Status::NotFound,
                    GenericAPIResponse {
                        message: "Notification not found.".to_string(),
                        error: true,
                    }
                );
            } else {
                generate_response!(
                    Status::InternalServerError,
                    GenericAPIResponse {
                        message: format!("Internal Server Error: {:?}", e),
                        error: true,
                    }
                );
            }
        }
    }
}
