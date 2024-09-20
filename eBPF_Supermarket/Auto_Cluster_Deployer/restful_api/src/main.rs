mod auth;
mod model;
mod servers;
mod server_groups;
mod server_group_members;
mod deployment_packages;
mod deployment_tasks;

use rocket::routes;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use rocket::{Request, Response};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::config::Config;


type Db = PgPool;

// 定义自定义 CORS Fairing
pub struct Cors {
    allowed_origins: Vec<String>,
}

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "CORS Fairing",
            kind: Kind::Response | Kind::Request,
        }
    }

    async fn on_request(&self, _request: &mut Request<'_>, _data: &mut rocket::Data<'_>) {
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        if request.method() == rocket::http::Method::Options {
            response.set_status(rocket::http::Status::Ok);
        }

        response.set_header(Header::new("Access-Control-Allow-Origin", self.get_origin(request)));
        response.set_header(Header::new("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "Authorization, Accept, Content-Type"));
    }
}

impl Cors {
    fn new(allowed_origins: Vec<&str>) -> Self {
        Cors {
            allowed_origins: allowed_origins.into_iter().map(String::from).collect(),
        }
    }

    fn get_origin(&self, request: &Request<'_>) -> String {
        if let Some(origin) = request.headers().get_one("Origin") {
            if self.allowed_origins.contains(&origin.to_string()) {
                return origin.to_string();
            }
        }
        "*".to_string() // 默认情况下允许所有来源
    }
}

#[rocket::options("/")]
fn options_route() -> rocket::http::Status {
    rocket::http::Status::Ok
}

// 配置并启动 Rocket
fn rocket(pool: Db) -> rocket::Rocket<rocket::Build> {
    let allowed_origins = vec![
        "http://localhost:8080",
        "http://192.168.31.145:8080",
    ];

    rocket::custom(
        Config::figment()
            .merge(("port", 8080))
            .merge(("address", "0.0.0.0"))
    )
    .manage(pool)
    .attach(Cors::new(allowed_origins))
    .mount("/", routes![
        options_route,
        auth::register,
        auth::login,
        auth::change_password,
        servers::add_server,
        servers::get_servers,
        servers::delete_server,
        server_groups::add_server_group,
        server_groups::get_server_groups,
        server_groups::delete_server_group,
        server_group_members::add_servers_to_group,
        server_group_members::get_servers_in_group,
        server_group_members::remove_servers_from_group, 
        deployment_packages::add_deployment_package,
        deployment_packages::get_deployment_packages,
        deployment_packages::get_all_deployment_packages,
        deployment_packages::update_deployment_package,
        deployment_packages::delete_deployment_package,
        deployment_tasks::add_deployment_task, 
        deployment_tasks::get_all_deployment_tasks,  
        deployment_tasks::get_deployment_tasks_by_package,
        deployment_tasks::update_deployment_task, 
        deployment_tasks::delete_deployment_task, 
    ])
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://zxy:123456@localhost/sensordb")
        .await
        .expect("Failed to create pool.");

    rocket(pool).launch().await?;

    Ok(())
}
