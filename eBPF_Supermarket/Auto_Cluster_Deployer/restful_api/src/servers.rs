use rocket::{get, post,delete, serde::json::Json, State};
use crate::model::{Server, NewServer, ApiResponse};
use sqlx::{PgPool, query_as, query};
use rocket::http::Status;

// 增加服务器
#[post("/servers", data = "<new_server>")]
pub async fn add_server(db: &State<PgPool>, new_server: Json<NewServer>) -> Result<Json<ApiResponse<Server>>, Status> {
    let result = query_as::<_, Server>(
        "INSERT INTO servers (ip_address) VALUES ($1) RETURNING *"
    )
    .bind(&new_server.ip_address)
    .fetch_one(&**db)
    .await;

    match result {
        Ok(server) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Server added successfully".to_string(),
            data: Some(server),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 查询所有服务器
#[get("/servers")]
pub async fn get_servers(db: &State<PgPool>) -> Result<Json<ApiResponse<Vec<Server>>>, Status> {
    let result = query_as::<_, Server>("SELECT * FROM servers")
        .fetch_all(&**db)
        .await;

    match result {
        Ok(servers) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Servers retrieved successfully".to_string(),
            data: Some(servers),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}


#[delete("/servers/<ip_address>")]
pub async fn delete_server(db: &State<PgPool>, ip_address: &str) -> Result<Json<ApiResponse<()>>, Status> {
    let result = query("DELETE FROM servers WHERE ip_address = $1")
        .bind(ip_address)
        .execute(&**db)
        .await;

    match result {
        Ok(_) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Server deleted successfully".to_string(),
            data: None,
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

