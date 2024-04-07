pub mod internal_types {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Deserialize, Serialize, Clone, PartialEq)]
    pub struct NotificationInformation {
        pub read: bool,
        pub title: String,
        pub info: String,
        pub from_user_id: String,
        pub uid: String,
        pub remove_by: String,
    }

    #[derive(Deserialize, Serialize, Clone, PartialEq)]
    pub struct DeviceInformation {
        pub device_name: String,
        pub device_id: String,
        pub ps_data: HashMap<String, (Vec<u8>, String)>,
    }

    #[derive(Deserialize, Serialize, Clone, PartialEq)]
    pub struct UserInformation {
        pub username: String,
        pub pfp: String,
        pub friend_code: String,
        pub friends: Vec<UsernameMap>,
        pub notifications: Vec<NotificationInformation>,
        pub password_hashed: String,
        pub salt: String,
        pub user_id: String,
        pub devices: Vec<DeviceInformation>,
        pub secret: String,
    }

    #[derive(Deserialize, Serialize, Clone, PartialEq)]
    pub struct UsernameMap {
        pub owner_id: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct DateReportingInfo {
        pub times: u8,
    }
}

pub mod recieveable_types {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct CreateAccountProps {
        pub username: String,
        pub password: String,
    }

    #[derive(Deserialize)]
    pub struct LoginProps {
        pub username: String,
        pub password: String,
        pub requested_scopes: Vec<String>,
    }

    #[derive(Deserialize)]
    pub struct ChangePasswordProps {
        pub username: String,
        pub old_password: String,
        pub new_password: String,
    }
}

pub mod sendable_types {
    use serde::Serialize;

    #[derive(Serialize, Clone)]
    pub struct StrippedNotificationInformation {
        pub read: bool,
        pub title: String,
        pub info: String,
        pub pfp: String,
        pub uid: String,
    }

    #[derive(Serialize, Clone, PartialEq)]
    pub struct ProcessedDeviceInformation {
        pub device_name: String,
        pub device_id: String,
        pub line_graph_labels: Vec<String>,
        pub line_graph_values: Vec<u8>,
    }

    #[derive(Serialize, Clone)]
    pub struct StrippedUserInformation {
        pub username: String,
        pub pfp: String,
        pub friend_code: String,
        pub devices: Vec<ProcessedDeviceInformation>,
    }

    #[derive(Serialize, Clone)]
    pub struct ExpandedStrippedUserInformation {
        pub username: String,
        pub friends: Vec<StrippedUserInformation>,
        pub friend_code: String,
        pub devices: Vec<ProcessedDeviceInformation>,
        pub notifications: Vec<StrippedNotificationInformation>,
        pub pfp: String,
    }

    #[derive(Serialize, Debug)]
    pub struct GenericAPIResponse {
        pub message: String,
        pub error: bool,
    }

    impl ToString for GenericAPIResponse {
        fn to_string(&self) -> String {
            serde_json::to_string(self).unwrap()
        }
    }
}
