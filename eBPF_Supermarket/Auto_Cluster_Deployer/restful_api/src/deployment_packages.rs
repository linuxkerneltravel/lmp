use rocket::{get, post, put, delete, serde::json::Json, State};
use crate::model::{DeploymentPackage, NewDeploymentPackage, ApiResponse};
use sqlx::{PgPool, query_as, query};
use rocket::http::Status;

// 增加部署包
#[post("/deployment_packages", data = "<new_package>")]
pub async fn add_deployment_package(
    db: &State<PgPool>, 
    new_package: Json<NewDeploymentPackage>
) -> Result<Json<ApiResponse<DeploymentPackage>>, Status> {
    let result = query_as::<_, DeploymentPackage>(
        "INSERT INTO deployment_packages (version, software_name, description, path) 
        VALUES ($1, $2, $3, $4) RETURNING *"
    )
    .bind(&new_package.version)
    .bind(&new_package.software_name)
    .bind(&new_package.description)
    .bind(&new_package.path)
    .fetch_one(&**db)
    .await;

    match result {
        Ok(package) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment package added successfully".to_string(),
            data: Some(package),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 查询部署包（根据软件名）
#[get("/deployment_packages/<software_name>")]
pub async fn get_deployment_packages(
    db: &State<PgPool>, 
    software_name: String
) -> Result<Json<ApiResponse<Vec<DeploymentPackage>>>, Status> {
    let result = query_as::<_, DeploymentPackage>(
        "SELECT * FROM deployment_packages WHERE software_name = $1"
    )
    .bind(&software_name)
    .fetch_all(&**db)
    .await;

    match result {
        Ok(packages) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment packages retrieved successfully".to_string(),
            data: Some(packages),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 获取全部部署包
#[get("/deployment_packages")]
pub async fn get_all_deployment_packages(
    db: &State<PgPool>
) -> Result<Json<ApiResponse<Vec<DeploymentPackage>>>, Status> {
    let result = query_as::<_, DeploymentPackage>(
        "SELECT * FROM deployment_packages"
    )
    .fetch_all(&**db)
    .await;

    match result {
        Ok(packages) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "All deployment packages retrieved successfully".to_string(),
            data: Some(packages),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 修改部署包（根据软件名）
#[put("/deployment_packages/<software_name>", data = "<updated_package>")]
pub async fn update_deployment_package(
    db: &State<PgPool>, 
    software_name: String, 
    updated_package: Json<NewDeploymentPackage>
) -> Result<Json<ApiResponse<DeploymentPackage>>, Status> {
    let result = query_as::<_, DeploymentPackage>(
        "UPDATE deployment_packages 
        SET version = $1, description = $2, path = $3 
        WHERE software_name = $4 
        RETURNING *"
    )
    .bind(&updated_package.version)
    .bind(&updated_package.description)
    .bind(&updated_package.path)
    .bind(&software_name)
    .fetch_one(&**db)
    .await;

    match result {
        Ok(package) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment package updated successfully".to_string(),
            data: Some(package),
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

// 删除部署包（根据软件名）
#[delete("/deployment_packages/<software_name>")]
pub async fn delete_deployment_package(
    db: &State<PgPool>, 
    software_name: String
) -> Result<Json<ApiResponse<()>>, Status> {
    let result = query("DELETE FROM deployment_packages WHERE software_name = $1")
        .bind(&software_name)
        .execute(&**db)
        .await;

    match result {
        Ok(_) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Deployment package deleted successfully".to_string(),
            data: None,
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}

