use rocket::{post, serde::json::Json, State};
use crate::model::{User, NewUser, ApiResponse};
use sqlx::query_as;
use bcrypt::{hash, verify};
use chrono::Utc;
use rocket::http::Status;
use sqlx::PgPool;
use crate::model::ChangePasswordRequest; 
use sqlx::query;  

#[post("/register", data = "<new_user>")]
pub async fn register(db: &State<PgPool>, new_user: Json<NewUser>) -> Result<Json<ApiResponse<User>>, Status> {
    let password_hash = hash(&new_user.password, 4).map_err(|_| Status::InternalServerError)?;

    let mut conn = db.acquire().await.map_err(|_| Status::InternalServerError)?;

    let result = query_as::<_, User>(
        r#"
        INSERT INTO users (username, password_hash, created_at, updated_at)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#
    )
    .bind(&new_user.username)
    .bind(&password_hash)
    .bind(Utc::now())
    .bind(Utc::now())
    .fetch_one(&mut conn)
    .await;

    match result {
        Ok(user) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "User registered successfully".to_string(),
            data: Some(user),
        })),
        Err(sqlx::Error::Database(db_err)) if db_err.constraint() == Some("unique_username") => {
            // 处理唯一约束冲突错误
            Err(Status::Conflict) // 返回 409 冲突状态
        },
        Err(_) => Err(Status::UnprocessableEntity),
    }
}


#[post("/login", data = "<login_data>")]
pub async fn login(db: &State<PgPool>, login_data: Json<NewUser>) -> Result<Json<ApiResponse<User>>, Status> {
    let mut conn = db.acquire().await.map_err(|_| Status::InternalServerError)?;

    let user = query_as::<_, User>(
        r#"
        SELECT id, username, password_hash, created_at, updated_at
        FROM users
        WHERE username = $1
        "#
    )
    .bind(&login_data.username)
    .fetch_optional(&mut conn)  // 使用获取的连接
    .await
    .map_err(|_| Status::InternalServerError)?
    .ok_or_else(|| Status::Unauthorized)?;

    let valid = verify(&login_data.password, &user.password_hash).map_err(|_| Status::InternalServerError)?;

    if valid {
        Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Login successful".to_string(),
            data: Some(user),
        }))
    } else {
        Err(Status::Unauthorized)
    }
}

// 修改密码接口
#[post("/change_password", data = "<change_password_request>")]
pub async fn change_password(
    db: &State<PgPool>,
    change_password_request: Json<ChangePasswordRequest>,
) -> Result<Json<ApiResponse<()>>, Status> {
    let mut conn = db.acquire().await.map_err(|_| Status::InternalServerError)?;

    // 获取用户信息
    let user = query_as::<_, User>(
        r#"
        SELECT id, username, password_hash, created_at, updated_at
        FROM users
        WHERE username = $1
        "#
    )
    .bind(&change_password_request.username)
    .fetch_optional(&mut conn)
    .await
    .map_err(|_| Status::InternalServerError)?
    .ok_or_else(|| Status::Unauthorized)?;

    // 验证旧密码
    let is_valid = verify(&change_password_request.old_password, &user.password_hash)
        .map_err(|_| Status::InternalServerError)?;

    if !is_valid {
        return Err(Status::Unauthorized); // 如果旧密码不正确，返回未授权状态
    }

    // 哈希新密码
    let new_password_hash = hash(&change_password_request.new_password, 4)
        .map_err(|_| Status::InternalServerError)?;

    // 更新数据库中的密码哈希
    let update_result = query(
        r#"
        UPDATE users
        SET password_hash = $1, updated_at = $2
        WHERE id = $3
        "#
    )
    .bind(&new_password_hash)
    .bind(chrono::Utc::now())
    .bind(user.id)
    .execute(&mut conn)
    .await;

    match update_result {
        Ok(_) => Ok(Json(ApiResponse {
            code: 200,
            status: "success".to_string(),
            message: "Password updated successfully".to_string(),
            data: None,
        })),
        Err(_) => Err(Status::InternalServerError),
    }
}
