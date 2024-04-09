# DuckAPI - DuckPowered's Offical API

## What is DuckAPI?

DuckAPI is DuckPowered's official API. It is a RESTful API that allows you to interact with DuckPowered's services. It provides the means for DuckID authentication, user-to-user interaction and cloud-based device syncing.

## How do I host DuckAPI?

DuckAPI is a Rust application, so you'll first need to install Rust and Cargo. You can then clone this repository and run `cargo run` to start the server. You can also build the server with `cargo build`. It's recommended to use `cargo run --release` in production.

However, before the API will work, you'll need to set up DuckAPI's filesystem database. You can do this by creating the following directories, depending on your operating system. All environment variables should be based off the user account under which you wish to run DuckAPI. 

- Windows: `{FOLDERID_RoamingAppData}/DuckPoweredServer`
- macOS: `$HOME/Library/Application Support/DuckPoweredServer`
- Linux: `$XDG_DATA_HOME/DuckPoweredServer` or `$HOME/.local/share/DuckPoweredServer`

In the `DuckPoweredServer`, then create the following subdirectories:

- `Users`
- `UsernameMaps`
- `FriendCodeMaps`
- `DailyReporting`

You must also set the following environment variables:
- `JWT_SIGNING_KEY` - The key used to sign JWTs. This should be a random string of at least 32 characters.

## How do I use DuckAPI?

DuckAPI is a RESTful API, so you can use it with any programming language that supports HTTP requests. Our offical JavaScript/TypeScript package, used by the actual DuckPowered application, is avaliable on NPM under the name [`duckapi-client`](https://github.com/IntegralPilot/duckapi-client).

We're working on a full API documentation, but for now, you can look at the source code or [`duckapi-client`](https://github.com/IntegralPilot/duckapi-client) to see what endpoints are avaliable and the expected request and response bodies/headers.

## How do I contribute to DuckAPI?

We're always looking for contributors to DuckAPI! If you'd like to contribute, please fork this repository and make a pull request. We'll review your changes and merge them if they're good. Please make sure to follow our code of conduct and our contribution guidelines.

Additonally, if you find any bugs when using DuckAPI, please open an issue on this repository. We'll look into it and fix it as soon as possible. If you are using [`duckapi-client`](https://github.com/IntegralPilot/duckapi-client) or the actual DuckPowered App/CLI interface, please open an issue on the relevant repository instead, and, if it turns out to be a bug in DuckAPI, we'll redirect you here.

## Integration and Unit Testing

Our full test suite (which covers every API route) is integrated with the [`duckapi-client`](https://github.com/IntegralPilot/duckapi-client) package, which is used by the actual DuckPowered application. This package is avaliable on NPM under the name [`duckapi-client`](https://github.com/IntegralPilot/duckapi-client). If you're making changes to DuckAPI, please make sure to run the tests in the [`duckapi-client`](https://github.com/IntegralPilot/duckapi-client)` package to ensure that nothing is broken. Otherwise, your PR will be denied.

The tests there will assume that DuckAPI is running on `localhost:8000` and can be run through `npm test`.
