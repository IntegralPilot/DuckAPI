#[macro_use]
extern crate rocket;

mod handlers;
use handlers::{
    change_password_route, create_account_route, create_device_route, destroy_account_route, destroy_device_route, friend_adder_route, friend_remover_route, increment_number_of_dau_background, increment_number_of_dau_foreground, login_route, new_notification_route, notifcation_read_marker_route, ping_route, refresh_route, update_device_name_route, update_device_ps_route, update_pfp_route, update_status_route, update_username_route, user_information_collator_route
};

use dotenv::dotenv;

mod catchers;

use catchers::{bad_request, forbidden, internal_error, not_found, unauthorized};

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    rocket::build()
    .register("/api/v1", catchers![
        bad_request,
        unauthorized,
        forbidden,
        not_found,
        internal_error
    ])
    .mount(
        "/api/v1",
        routes![
            update_status_route,
            ping_route,
            create_account_route,
            login_route,
            refresh_route,
            change_password_route,
            create_device_route,
            update_device_name_route,
            update_device_ps_route,
            destroy_device_route,
            increment_number_of_dau_foreground,
            increment_number_of_dau_background,
            destroy_account_route,
            user_information_collator_route,
            friend_adder_route,
            friend_remover_route,
            notifcation_read_marker_route,
            update_username_route,
            update_pfp_route,
            new_notification_route
        ]
    )
}
