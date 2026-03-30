use sqlx::postgres::PgPoolOptions;

pub fn get_database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/keri_controller_test".to_string())
}

/// Drops and recreates the test database once per test binary so each run starts fresh.
pub fn ensure_clean_db() {
    static INIT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
    let mut done = INIT.lock().unwrap();
    if *done {
        return;
    }
    let result = std::panic::catch_unwind(|| {
        async_std::task::block_on(async {
            let url = get_database_url();
            let (base, db_name) = url.rsplit_once('/').expect("Invalid DATABASE_URL");
            let admin = PgPoolOptions::new()
                .max_connections(2)
                .connect(&format!("{}/postgres", base))
                .await
                .expect("Failed to connect to admin db");
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", db_name))
                .execute(&admin)
                .await;
            sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
                .execute(&admin)
                .await
                .expect("Failed to create test database");
        });
    });
    if result.is_err() {
        panic!("ensure_clean_db failed — check DATABASE_URL and postgres connection");
    }
    *done = true;
}
