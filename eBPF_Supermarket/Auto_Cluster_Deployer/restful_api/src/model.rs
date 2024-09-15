use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;


#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password: String,
}


#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub username: String,
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Server {
    pub id: i32,
    pub ip_address: String,
}

#[derive(Debug, Deserialize)]
pub struct NewServer {
    pub ip_address: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct ServerGroup {
    pub id: i32,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct NewServerGroup {
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct ServerGroupMember {
    pub id: i32,
    pub server_id: i32,
    pub group_id: i32,
}

#[derive(Debug, Deserialize)]
pub struct BatchAddServersRequest {
    pub ip_addresses: Vec<String>, 
    pub group_description: String, 
}


#[derive(Debug, Deserialize)]
pub struct BatchRemoveServersRequest {
    pub ip_addresses: Vec<String>, 
    pub group_description: String, 
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct DeploymentPackage {
    pub id: i32,
    pub version: String,
    pub software_name: String,
    pub description: Option<String>,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct NewDeploymentPackage {
    pub version: String,
    pub software_name: String,
    pub description: Option<String>,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct DeploymentTask {
    pub id: i32,
    pub package_id: i32,
    pub target_type: String,
    pub target_id: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct NewDeploymentTask {
    pub package_id: i32,
    pub target_type: String,
    pub target_id: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    SingleServer,
    ServerGroup,
    All,
}

impl TargetType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "单台服务器" => Some(TargetType::SingleServer),
            "服务器组" => Some(TargetType::ServerGroup),
            "所有" => Some(TargetType::All),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub code: u16,
    pub status: String,
    pub message: String,
    pub data: Option<T>,
}
