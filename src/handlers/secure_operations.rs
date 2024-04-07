use rand::{distributions::Alphanumeric, Rng};

pub async fn rng_alphanumeric(chars: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(chars)
        .map(char::from)
        .collect()
}

pub mod password_handling {
    use super::super::user_operations::actually_change_password;
    use super::Rng;
    use rand::distributions::Alphanumeric;
    use ring::digest::{digest, SHA512};

    pub struct SecureHash {
        pub hash: String,
        pub salt: String,
    }

    pub async fn hash_password(password: &str) -> SecureHash {
        let salt: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(50)
            .map(char::from)
            .collect();

        let salted_password = format!("{}{}", password, salt);

        let hash = digest(&SHA512, salted_password.as_bytes());

        SecureHash {
            hash: hex::encode(hash.as_ref()),
            salt,
        }
    }

    pub async fn verify_password(password: &str, salt: &str, stored_hash: &str) -> bool {
        let salted_password = format!("{}{}", password, salt);
        let hash = digest(&SHA512, salted_password.as_bytes());
        hex::encode(hash.as_ref()) == stored_hash
    }

    pub async fn test_if_password_meets_requirements(password: &str) -> bool {
        if password.len() < 8 {
            return false;
        }

        if !password.chars().any(|c| c.is_uppercase()) {
            return false;
        }

        if !password.chars().any(|c| c.is_lowercase()) {
            return false;
        }

        if !password.chars().any(|c| c.is_numeric()) {
            return false;
        }

        if !password.chars().any(|c| !c.is_alphanumeric()) {
            return false;
        }

        true
    }

    pub async fn change_password(
        old_password_attempt: &str,
        salt: &str,
        stored_hash: &str,
        user_id: &str,
        new_password: &str,
    ) -> Result<(), String> {
        match test_if_password_meets_requirements(new_password).await {
            false => return Err(String::from("The new password does not meet the requirements. You must use at least 8 characters, including uppercase and lowercase letters, digits, and special characters.")),
            true => match verify_password(old_password_attempt, salt, stored_hash).await {
            false => return Err(String::from("The existing password is incorrect.")),
            true => match actually_change_password(user_id, new_password).await {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
        }
    }
    }
}

pub mod tokens {
    use hmac::{Hmac, Mac};
    use jwt::{SignWithKey, VerifyWithKey};
    use sha2::Sha256;
    use std::{collections::BTreeMap, str::FromStr};

    use crate::handlers::{
        request_guards::header_filtering::agent_information::DuckPoweredAuthInfo,
        user_operations::get_user_info_from_id_no_ps_increment,
    };

    #[derive(PartialEq)]
    pub enum DuckPoweredTokenType {
        Access,
        Refresh,
    }

    impl FromStr for DuckPoweredTokenType {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "a" => Ok(DuckPoweredTokenType::Access),
                "r" => Ok(DuckPoweredTokenType::Refresh),
                _ => Err(()),
            }
        }
    }

    impl ToString for DuckPoweredTokenType {
        fn to_string(&self) -> String {
            match self {
                DuckPoweredTokenType::Access => "a".to_string(),
                DuckPoweredTokenType::Refresh => "r".to_string(),
            }
        }
    }

    #[derive(PartialEq)]
    pub enum DuckPoweredTokenScope {
        CoreUserInfoRead,
        CoreUserInfoWrite,
        DevicesRead,
        DevicesWrite,
        FriendsReadNames,
        FriendsReadFullContent,
        FriendsWrite,
        NotificationsRead,
        NotificationsWrite,
    }

    impl FromStr for DuckPoweredTokenScope {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "cui.r" => Ok(DuckPoweredTokenScope::CoreUserInfoRead),
                "cui.w" => Ok(DuckPoweredTokenScope::CoreUserInfoWrite),
                "d.r" => Ok(DuckPoweredTokenScope::DevicesRead),
                "d.w" => Ok(DuckPoweredTokenScope::DevicesWrite),
                "f.r-lim" => Ok(DuckPoweredTokenScope::FriendsReadNames),
                "f.r" => Ok(DuckPoweredTokenScope::FriendsReadFullContent),
                "f.w" => Ok(DuckPoweredTokenScope::FriendsWrite),
                "n.r" => Ok(DuckPoweredTokenScope::NotificationsRead),
                "n.w" => Ok(DuckPoweredTokenScope::NotificationsWrite),
                _ => Err(()),
            }
        }
    }

    impl ToString for DuckPoweredTokenScope {
        fn to_string(&self) -> String {
            match self {
                DuckPoweredTokenScope::CoreUserInfoRead => "cui.r".to_string(),
                DuckPoweredTokenScope::CoreUserInfoWrite => "cui.w".to_string(),
                DuckPoweredTokenScope::DevicesRead => "d.r".to_string(),
                DuckPoweredTokenScope::DevicesWrite => "d.w".to_string(),
                DuckPoweredTokenScope::FriendsReadNames => "f.r-lim".to_string(),
                DuckPoweredTokenScope::FriendsReadFullContent => "f.r".to_string(),
                DuckPoweredTokenScope::FriendsWrite => "f.w".to_string(),
                DuckPoweredTokenScope::NotificationsRead => "n.r".to_string(),
                DuckPoweredTokenScope::NotificationsWrite => "n.w".to_string(),
            }
        }
    }

    pub struct DuckPoweredTokenScopes(pub Vec<DuckPoweredTokenScope>);

    impl FromStr for DuckPoweredTokenScopes {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let scopes: Vec<DuckPoweredTokenScope> = s
                .split(',')
                .map(|scope| DuckPoweredTokenScope::from_str(scope))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(DuckPoweredTokenScopes(scopes))
        }
    }

    impl ToString for DuckPoweredTokenScopes {
        fn to_string(&self) -> String {
            self.0
                .iter()
                .map(|scope| scope.to_string())
                .collect::<Vec<String>>()
                .join(",")
        }
    }

    pub struct DuckPoweredAuthClaim {
        pub token_type: DuckPoweredTokenType,
        pub scopes: DuckPoweredTokenScopes,
        pub for_uid: String,
        pub user_secret: String,
        pub valid_until: u64,
    }

    pub fn create_token(claim: DuckPoweredAuthClaim) -> Result<String, String> {
        let jwt_signing_key = std::env::var("JWT_SIGNING_KEY").map_err(|e| e.to_string())?;
        let key: Hmac<Sha256> =
            Hmac::new_from_slice(jwt_signing_key.as_bytes()).map_err(|e| e.to_string())?;
        let mut claims = BTreeMap::new();
        claims.insert("sub", claim.for_uid.as_str());
        let binding = claim.valid_until.to_string();
        claims.insert("exp", binding.as_str());
        let binding = claim.token_type.to_string();
        claims.insert("typ", binding.as_str());
        let binding = claim.scopes.to_string();
        claims.insert("scp", binding.as_str());
        claims.insert("sec", claim.user_secret.as_str());
        let token = claims.sign_with_key(&key).map_err(|e| e.to_string());
        token.map_err(|e| e.to_string())
    }

    pub async fn verify_token(token: &str) -> Result<DuckPoweredAuthInfo, String> {
        let jwt_signing_key = std::env::var("JWT_SIGNING_KEY").map_err(|e| e.to_string())?;
        let key: Hmac<Sha256> =
            Hmac::new_from_slice(jwt_signing_key.as_bytes()).map_err(|e| e.to_string())?;
        let claims: Result<BTreeMap<String, String>, jwt::Error> = token.verify_with_key(&key);

        let claims = claims.map_err(|e| e.to_string())?;

        let token_type = match claims.get("typ") {
            Some(typ) => {
                DuckPoweredTokenType::from_str(typ).map_err(|_| "Invalid token type".to_string())?
            }
            None => return Err("Token type not found".to_string()),
        };

        let scopes = match claims.get("scp") {
            Some(scp) => DuckPoweredTokenScopes::from_str(scp)
                .map_err(|_| "Invalid token scope".to_string())?,
            None => return Err("Token scope not found".to_string()),
        };

        let for_uid = match claims.get("sub") {
            Some(sub) => sub.to_string(),
            None => return Err("Subject not found in token".to_string()),
        };

        let user_info = get_user_info_from_id_no_ps_increment(for_uid.as_str()).await?;

        let valid_until = match claims.get("exp") {
            Some(exp) => exp
                .parse::<u64>()
                .map_err(|_| "Invalid expiration time".to_string())?,
            None => return Err("Expiration time not found".to_string()),
        };

        let user_secret = match claims.get("sec") {
            Some(sec) => sec.to_string(),
            None => return Err("User secret not found".to_string()),
        };

        if user_secret != user_info.secret {
            return Err("User secret does not match".to_string());
        }

        if valid_until < chrono::Utc::now().timestamp_millis() as u64 {
            return Err("The token has expired. Please generate a new one.".to_string());
        }

        Ok(DuckPoweredAuthInfo {
            claim: DuckPoweredAuthClaim {
                token_type,
                scopes,
                for_uid,
                user_secret,
                valid_until,
            },
            user_info,
        })
    }
}
