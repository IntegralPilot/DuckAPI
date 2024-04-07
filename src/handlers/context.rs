pub mod context {

    pub struct DuckPoweredContext {
        pub last_security_update_versioncode: u16,
        pub last_update_versioncode: u16,
    }

    // Static, never-changing data for the tests
    #[cfg(test)]
    pub const DUCKPOWERED_CONTEXT: DuckPoweredContext = DuckPoweredContext {
        last_security_update_versioncode: 2,
        last_update_versioncode: 3,
    };

    // Real, production data
    #[cfg(not(test))]
    pub const DUCKPOWERED_CONTEXT: DuckPoweredContext = DuckPoweredContext {
        last_security_update_versioncode: 200,
        last_update_versioncode: 200,
    };
}
