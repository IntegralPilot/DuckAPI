#[catch(400)]
pub fn bad_request() -> &'static str {
   "{\"error\": true, \"message\": \"The request was invalid.\"}"
}

#[catch(401)]
pub fn unauthorized() -> &'static str {
   "{\"error\": true, \"message\": \"You are not authorized to access this resource.\"}"
}

#[catch(403)]
pub fn forbidden() ->  &'static str {
   "{\"error\": true, \"message\": \"You do not have permission to access this resource.\"}"
}

#[catch(404)]
pub fn not_found() -> &'static str {
   "{\"error\": true, \"message\": \"The requested resource was not found.\"}"
}

#[catch(500)]
pub fn internal_error() -> &'static str {
   "{\"error\": true, \"message\": \"An internal server error occurred.\"}"
}