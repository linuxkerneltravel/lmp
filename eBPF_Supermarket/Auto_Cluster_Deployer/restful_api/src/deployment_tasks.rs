use crate::model::{DeploymentTask, NewDeploymentTask, ApiResponse, TargetType};
use sqlx::{PgPool, query_as, query};
use rocket::{get, post, put, delete, serde::json::Json, State};
use rocket::http::Status;

#[post("/deployment_tasks", data = "<new_task>")]
pub async fn add_deployment_task(
    db: &State<PgPool>,
    new_task: Json<NewDeploymentTask>
) -> Result<Json<ApiResponse<DeploymentTask>>, Status> {
    let target_type = TargetType::from_str(&new_task.target_type)
        .ok_or(Status::BadRequest)?;

    match target_type {
        TargetType::SingleServer => {
            let server_exists = query("SELECT 1 FROM servers WHERE id = $1")
                .bind(new_task.target_id)
                .fetch_optional(&**db)
                .await
                .map_err(|e| {
                    eprintln!("Database error: {}", e);
                    Status::InternalServerError
                })?;

            if server_exists.is_none() {
                return Err(Status::BadRequest);
            }
        },
        TargetType::ServerGroup => {
            let group_exists = query("SELECT 1 FROM server_groups WHERE id = $1")
                .bind(new_task.target_id)
                .fetch_optional(&**db)
                .await
                .map_err(|e| {
                    eprintln!("Database error: {}", e);
                    Status::InternalServerError
                })?;

            if group_exists.is_none() {
                return Err(Status::BadRequest);
            }
        },
        TargetType::All => {
            if new_task.target_id.is_some() {
                return Err(Status::BadRequest);
            }
        },
    }

    let result = query_as::<_, DeploymentTask>(
        "INSERT INTO deployment_tasks (package_id, target_type, target_id, is_deployed) 
        VALUES ($1, $2, $3, FALSE) RETURNING *"
    )
    .bind(new_task.package_id)
    .bind(new_task.target_type.clone())
    .bind(new_task.target_id)
    .fetch_one(&**db)
    .await;

    match result {
        Ok(task) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment task created successfully".to_string(),
            data: Some(task),
        })),
        Err(sqlx::Error::Database(db_err)) if db_err.constraint() == Some("deployment_tasks_package_id_target_type_target_id_key") => {
            Err(Status::Conflict)
        },
        Err(e) => {
            eprintln!("Database error: {}", e);
            Err(Status::InternalServerError)
        },
    }
}

// 查询所有部署任务
#[get("/deployment_tasks")]
pub async fn get_all_deployment_tasks(
    db: &State<PgPool>
) -> Result<Json<ApiResponse<Vec<DeploymentTask>>>, Status> {
    let result = query_as::<_, DeploymentTask>("SELECT * FROM deployment_tasks")
        .fetch_all(&**db)
        .await;

    match result {
        Ok(tasks) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment tasks retrieved successfully".to_string(),
            data: Some(tasks),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 根据 package_id 查询部署任务
#[get("/deployment_tasks/package/<package_id>")]
pub async fn get_deployment_tasks_by_package(
    db: &State<PgPool>, 
    package_id: i32
) -> Result<Json<ApiResponse<Vec<DeploymentTask>>>, Status> {
    let result = query_as::<_, DeploymentTask>("SELECT * FROM deployment_tasks WHERE package_id = $1")
        .bind(package_id)
        .fetch_all(&**db)
        .await;

    match result {
        Ok(tasks) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment tasks retrieved successfully".to_string(),
            data: Some(tasks),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 更新部署任务
#[put("/deployment_tasks/<id>", data = "<updated_task>")]
pub async fn update_deployment_task(
    db: &State<PgPool>,
    id: i32,
    updated_task: Json<NewDeploymentTask>
) -> Result<Json<ApiResponse<DeploymentTask>>, Status> {
    let result = query_as::<_, DeploymentTask>(
        "UPDATE deployment_tasks 
        SET package_id = $1, target_type = $2, target_id = $3 
        WHERE id = $4 
        RETURNING *"
    )
    .bind(updated_task.package_id)
    .bind(updated_task.target_type.to_string())
    .bind(updated_task.target_id)
    .bind(id)
    .fetch_one(&**db)
    .await;

    match result {
        Ok(task) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment task created successfully".to_string(),
            data: Some(task),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 删除部署任务
#[delete("/deployment_tasks/<id>")]
pub async fn delete_deployment_task(
    db: &State<PgPool>,
    id: i32
) -> Result<Json<ApiResponse<()>>, Status> {
    let result = query("DELETE FROM deployment_tasks WHERE id = $1")
        .bind(id)
        .execute(&**db)
        .await;

    match result {
        Ok(_) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment task deleted successfully".to_string(),
            data: None,
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}
