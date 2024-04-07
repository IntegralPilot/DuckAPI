pub mod header_filtering {
    pub mod agent_information {
        use rocket::http::Status;
        use rocket::request::{self, FromRequest, Outcome, Request};
        use std::str::FromStr;

        use crate::handlers::secure_operations::tokens::{verify_token, DuckPoweredAuthClaim};
        use crate::handlers::types::internal_types::UserInformation;
        use crate::handlers::types::sendable_types::GenericAPIResponse;
        pub struct DuckPoweredAgentInformation {
            pub name: String,
            pub flavour: String,
            pub version: u16,
        }

        #[rocket::async_trait]
        impl<'r> FromRequest<'r> for DuckPoweredAgentInformation {
            type Error = ();

            async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
                let agent = request.headers().get_one("User-Agent");
                match agent {
                    Some(agent) => {
                        let agent_parts: Vec<&str> = agent.split('/').collect();
                        if agent_parts.len() != 3 {
                            return Outcome::Success(DuckPoweredAgentInformation {
                                name: "Unknown".to_string(),
                                flavour: "Unknown".to_string(),
                                version: 0,
                            });
                        }
                        let name = agent_parts[0].to_string();
                        let version = u16::from_str(agent_parts[1]).unwrap_or(0);
                        let flavour = agent_parts[2].to_string();
                        return Outcome::Success(DuckPoweredAgentInformation {
                            name,
                            flavour,
                            version,
                        });
                    }
                    None => {
                        return Outcome::Success(DuckPoweredAgentInformation {
                            name: "Unknown".to_string(),
                            flavour: "Unknown".to_string(),
                            version: 0,
                        })
                    }
                }
            }
        }

        pub struct DuckPoweredAuthInfo {
            pub claim: DuckPoweredAuthClaim,
            pub user_info: UserInformation,
        }

        #[rocket::async_trait]
        impl<'r> FromRequest<'r> for DuckPoweredAuthInfo {
            type Error = GenericAPIResponse;

            async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
                let auth_header = request.headers().get_one("Authorization");
                // format is "Bearer <jwt token>"
                match auth_header {
                    Some(header) => {
                        let parts: Vec<&str> = header.split(' ').collect();
                        if parts.len() != 2 {
                            return Outcome::Error((
                                Status::BadRequest,
                                GenericAPIResponse {
                                    message: "Invalid Authorization header".to_string(),
                                    error: true,
                                },
                            ));
                        }
                        let token = parts[1];
                        match verify_token(token).await {
                            Ok(claim) => Outcome::Success(claim),
                            Err(e) => Outcome::Error((
                                Status::Unauthorized,
                                GenericAPIResponse {
                                    message: e.to_string(),
                                    error: true,
                                },
                            )),
                        }
                    }
                    None => Outcome::Error((
                        Status::BadRequest,
                        GenericAPIResponse {
                            message: "No Authorization header".to_string(),
                            error: true,
                        },
                    )),
                }
            }
        }
    }
}
