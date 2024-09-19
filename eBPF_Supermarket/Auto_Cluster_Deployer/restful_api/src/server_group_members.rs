// server_group_members.rs

use rocket::{get, post, delete, serde::json::Json, State};
use crate::model::{ServerGroupMember, BatchAddServersRequest,BatchRemoveServersRequest, ApiResponse, Server, ServerGroup};
use sqlx::{PgPool, query_as, query};
use rocket::http::Status;

// 通用接口：添加一个或多个服务器到服务器组
#[post("/add_servers_to_group", data = "<request>")]
pub async fn add_servers_to_group(
    db: &State<PgPool>, 
    request: Json<BatchAddServersRequest>
) -> Result<Json<ApiResponse<Vec<ServerGroupMember>>>, Status> {
    // 查找目标服务器组
    let group = query_as::<_, ServerGroup>("SELECT * FROM server_groups WHERE description = $1")
        .bind(&request.group_description)
        .fetch_one(&**db)
        .await
        .map_err(|_| Status::NotFound)?;

    let mut added_members = vec![]; // 存储成功添加的成员记录

    // 逐个查找服务器并添加到组
    for ip in &request.ip_addresses {
        // 查找服务器
        let server = query_as::<_, Server>("SELECT * FROM servers WHERE ip_address = $1")
            .bind(ip)
            .fetch_one(&**db)
            .await
            .map_err(|_| Status::NotFound)?;

        // 插入关联关系
        match query_as::<_, ServerGroupMember>(
            "INSERT INTO server_group_members (server_id, group_id) VALUES ($1, $2) RETURNING *"
        )
        .bind(server.id)
        .bind(group.id)
        .fetch_one(&**db)
        .await {
            Ok(member) => added_members.push(member), // 成功时将成员添加到结果集中
            Err(_) => continue, // 如果插入失败，继续处理下一个
        }
    }

    // 如果没有成功添加的成员，返回错误
    if added_members.is_empty() {
        return Err(Status::UnprocessableEntity);
    }

    // 返回成功添加的成员记录
    Ok(Json(ApiResponse {
        code: 200,
        status: "success".to_string(),
        message: format!("Successfully added {} servers to group.", added_members.len()),
        data: Some(added_members),
    }))
}

// 查看服务器组中的所有服务器
#[get("/server_group_members/<description>")]
pub async fn get_servers_in_group(
    db: &State<PgPool>, 
    description: String
) -> Result<Json<ApiResponse<Vec<Server>>>, Status> {
    // 查询服务器组
    let group = query_as::<_, ServerGroup>("SELECT * FROM server_groups WHERE description = $1")
        .bind(&description)
        .fetch_one(&**db)
        .await
        .map_err(|_| Status::NotFound)?;

    // 查询该组下的所有服务器
    let result = query_as::<_, Server>(
        "SELECT s.* FROM servers s 
         JOIN server_group_members m ON s.id = m.server_id 
         WHERE m.group_id = $1"
    )
    .bind(group.id)
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

// 批量从服务器组中移除服务器
#[delete("/remove_servers_from_group", data = "<request>")]
pub async fn remove_servers_from_group(
    db: &State<PgPool>, 
    request: Json<BatchRemoveServersRequest>
) -> Result<Json<ApiResponse<()>>, Status> {
    // 查找目标服务器组
    let group = query_as::<_, ServerGroup>("SELECT * FROM server_groups WHERE description = $1")
        .bind(&request.group_description)
        .fetch_one(&**db)
        .await
        .map_err(|_| Status::NotFound)?;

    let mut removed_count = 0; // 记录成功移除的服务器数量

    // 逐个查找服务器并移除其与服务器组的关系
    for ip in &request.ip_addresses {
        // 查找服务器
        let server = query_as::<_, Server>("SELECT * FROM servers WHERE ip_address = $1")
            .bind(ip)
            .fetch_one(&**db)
            .await
            .map_err(|_| Status::NotFound)?;

        // 删除关联关系
        match query(
            "DELETE FROM server_group_members WHERE server_id = $1 AND group_id = $2"
        )
        .bind(server.id)
        .bind(group.id)
        .execute(&**db)
        .await {
            Ok(_) => removed_count += 1, // 成功时增加计数
            Err(_) => continue, // 如果删除失败，继续处理下一个
        }
    }

    // 如果没有成功移除的服务器，返回错误
    if removed_count == 0 {
        return Err(Status::UnprocessableEntity);
    }

    // 返回成功移除的结果
    Ok(Json(ApiResponse {
        code: 200,
        status: "success".to_string(),
        message: format!("Successfully removed {} servers from group.", removed_count),
        data: None,
    }))
}