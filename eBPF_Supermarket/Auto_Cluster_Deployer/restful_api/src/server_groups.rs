
use rocket::{get, post, delete, serde::json::Json, State};
use crate::model::{ServerGroup, NewServerGroup, ApiResponse};
use sqlx::{PgPool, query_as, query};
use rocket::http::Status;

// 增加服务器组
#[post("/server_groups", data = "<new_group>")]
pub async fn add_server_group(db: &State<PgPool>, new_group: Json<NewServerGroup>) -> Result<Json<ApiResponse<ServerGroup>>, Status> {
    let result = query_as::<_, ServerGroup>(
        "INSERT INTO server_groups (description) VALUES ($1) RETURNING *"
    )
    .bind(&new_group.description)
    .fetch_one(&**db)
    .await;

    match result {
        Ok(group) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Server group added successfully".to_string(),
            data: Some(group),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 查询所有服务器组
#[get("/server_groups")]
pub async fn get_server_groups(db: &State<PgPool>) -> Result<Json<ApiResponse<Vec<ServerGroup>>>, Status> {
    let result = query_as::<_, ServerGroup>("SELECT * FROM server_groups")
        .fetch_all(&**db)
        .await;

    match result {
        Ok(groups) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Server groups retrieved successfully".to_string(),
            data: Some(groups),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}


// 删除服务器组
#[delete("/server_groups/<id>")]
pub async fn delete_server_group(db: &State<PgPool>, id: i32) -> Result<Json<ApiResponse<()>>, Status> {
    let result = query("DELETE FROM server_groups WHERE id = $1")
        .bind(id)
        .execute(&**db)
        .await;

    match result {
        Ok(_) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Server group deleted successfully".to_string(),
            data: None,
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}
