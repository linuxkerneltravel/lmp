use sacontrol::{Empty, SaInfo, Ack, FileChunk, PackageRequest, IpRequest, PackageInfoResponse};
use sacontrol::sa_control_server::{SaControl, SaControlServer};
use tonic::{Request, Response, Status};
use tonic::transport::Server;
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, BufReader};
use tokio_postgres::NoTls;
use serde::{Deserialize, Serialize};
use tokio::fs::File as TokioFile;

pub mod sacontrol {
    tonic::include_proto!("sacontrol");
}

#[derive(Debug, Default)]
pub struct MySAControl;

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    program_directory: Vec<ProgramDirectory>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProgramDirectory {
    name: String,
    subdirectories: Vec<String>,
    paths: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TasksConfig {
    task_list: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TaskOutput {
    task: String,
    output: String,
    success: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct Agent {
    id: String,
    name: String,
}

#[tonic::async_trait]
impl SaControl for MySAControl {
    async fn deploy_packages(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Ack>, Status> {
        // 连接到 PostgreSQL 数据库
        let (client, connection) =
            tokio_postgres::connect("host=localhost port=5432 dbname=sensordb user=zxy password=123456", NoTls)
                .await
                .map_err(|e| Status::internal(format!("数据库连接失败: {}", e)))?;

        // 启动异步任务处理数据库连接
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("数据库连接错误: {}", e);
            }
        });

        // 查询 deployment_tasks 表
        let query_tasks = "SELECT id, package_id, target_type, target_id FROM deployment_tasks WHERE is_deployed != 't'";
        let rows = client.query(query_tasks, &[])
            .await
            .map_err(|e| Status::internal(format!("数据库查询失败: {}", e)))?;

        for row in rows {
            let id: i32 = row.get("id");
            let package_id: i32 = row.get("package_id");
            let target_type: String = row.get("target_type");
            let target_id: Option<i32> = row.get("target_id");

            if target_type == "所有" {
                // 对于 "所有"，获取所有服务器的 IP 地址并插入到 package_deployment 表
                let query_servers = "SELECT ip_address FROM servers";
                let server_rows = client.query(query_servers, &[])
                    .await
                    .map_err(|e| Status::internal(format!("查询 servers 失败: {}", e)))?;

                for server_row in server_rows {
                    let ip_address: String = server_row.get("ip_address");

                    // 插入到 package_deployment 表
                    client.execute(
                        "INSERT INTO package_deployment (package_id, ip_address) VALUES ($1, $2) 
                         ON CONFLICT (ip_address) DO UPDATE SET package_id = EXCLUDED.package_id",
                        &[&package_id, &ip_address],
                    ).await.map_err(|e| Status::internal(format!("插入 package_deployment 失败: {}", e)))?;
                }
            } else if target_type == "服务器组" {
                // 查找 server_group_members 中的 server_id
                if let Some(target_id) = target_id {
                    let query_group_members = "SELECT server_id FROM server_group_members WHERE group_id = $1";
                    let group_rows = client.query(query_group_members, &[&target_id])
                        .await
                        .map_err(|e| Status::internal(format!("查询 server_group_members 失败: {}", e)))?;

                    for group_row in group_rows {
                        let server_id: i32 = group_row.get("server_id");

                        // 查找 servers 中的 ip_address
                        let query_servers = "SELECT ip_address FROM servers WHERE id = $1";
                        let server_rows = client.query(query_servers, &[&server_id])
                            .await
                            .map_err(|e| Status::internal(format!("查询 servers 失败: {}", e)))?;

                        if let Some(server_row) = server_rows.get(0) {
                            let ip_address: String = server_row.get("ip_address");

                            // 将结果插入到 package_deployment 表中
                            client.execute(
                                "INSERT INTO package_deployment (package_id, ip_address) VALUES ($1, $2) 
                                 ON CONFLICT (ip_address) DO UPDATE SET package_id = EXCLUDED.package_id",
                                &[&package_id, &ip_address],
                            ).await.map_err(|e| Status::internal(format!("插入 package_deployment 失败: {}", e)))?;
                        }
                    }
                }
            } else if target_type == "单台服务器" {
                // 查找 servers 中的 ip_address
                if let Some(target_id) = target_id {
                    let query_servers = "SELECT ip_address FROM servers WHERE id = $1";
                    let server_rows = client.query(query_servers, &[&target_id])
                        .await
                        .map_err(|e| Status::internal(format!("查询 servers 失败: {}", e)))?;

                    if let Some(server_row) = server_rows.get(0) {
                        let ip_address: String = server_row.get("ip_address");

                        // 将结果插入到 package_deployment 表中
                        client.execute(
                            "INSERT INTO package_deployment (package_id, ip_address) VALUES ($1, $2) 
                             ON CONFLICT (ip_address) DO UPDATE SET package_id = EXCLUDED.package_id",
                            &[&package_id, &ip_address],
                        ).await.map_err(|e| Status::internal(format!("插入 package_deployment 失败: {}", e)))?;
                    }
                }
            }

            // 更新 deployment_tasks 表中的 is_deployed 为 true
            client.execute(
                "UPDATE deployment_tasks SET is_deployed = 't' WHERE id = $1",
                &[&id],
            ).await.map_err(|e| Status::internal(format!("更新 deployment_tasks 失败: {}", e)))?;
        }

        // 返回成功的 Ack 响应
        Ok(Response::new(Ack { success: true }))
    }

    async fn get_package_info_by_ip(
        &self,
        request: Request<IpRequest>,
    ) -> Result<Response<PackageInfoResponse>, Status> {
        let ip_address = request.into_inner().ip_address;

        // 连接到 PostgreSQL 数据库
        let (client, connection) =
            tokio_postgres::connect("host=localhost port=5432 dbname=sensordb user=zxy password=123456", NoTls)
                .await
                .map_err(|e| Status::internal(format!("数据库连接失败: {}", e)))?;

        // 启动异步任务处理数据库连接
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("数据库连接错误: {}", e);
            }
        });

        // 创建一个用于超时的计时器
        let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(5));

        tokio::select! {
            _ = timeout => {
                // 超时后返回 ID 为 -1 的响应
                Ok(Response::new(PackageInfoResponse {
                    id: -1,
                    version: "".to_string(),
                    software_name: "".to_string(),
                    description: "".to_string(),
                }))
            }
            result = async {
                loop {
                    // 查询 package_deployment 表
                    let query_package_deployment = "SELECT package_id FROM package_deployment WHERE ip_address = $1";
                    let rows = client.query(query_package_deployment, &[&ip_address])
                        .await
                        .map_err(|e| Status::internal(format!("查询 package_deployment 失败: {}", e)))?;

                    if let Some(row) = rows.get(0) {
                        let package_id: i32 = row.get(0);

                        // 查询 deployment_packages 表，获取 id、version、software_name 和 description
                        let query_deployment_packages = "SELECT id, version, software_name, description FROM deployment_packages WHERE id = $1";
                        let rows = client.query(query_deployment_packages, &[&package_id])
                            .await
                            .map_err(|e| Status::internal(format!("查询 deployment_packages 失败: {}", e)))?;

                        // 处理查询结果
                        if let Some(row) = rows.get(0) {
                            let id: i32 = row.get("id");  // 获取 id
                            let version: String = row.get("version");
                            let software_name: String = row.get("software_name");
                            let description: String = row.get("description");

                            // 删除 package_deployment 表中与该 IP 地址相关的记录
                            client.execute(
                                "DELETE FROM package_deployment WHERE ip_address = $1",
                                &[&ip_address],
                            )
                            .await
                            .map_err(|e| Status::internal(format!("删除 package_deployment 记录失败: {}", e)))?;

                            // 返回查询结果
                            return Ok(Response::new(PackageInfoResponse {
                                id,
                                version,
                                software_name,
                                description,
                            }));
                        } else {
                            // 没有找到包信息，继续循环
                            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        }
                    } else {
                        // 没有找到相关的包部署记录，继续循环
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            } => result,
        }
    }

    async fn sa_regist(
        &self,
        request: Request<SaInfo>,
    ) -> Result<Response<Ack>, Status> {
        let sa_info = request.into_inner();
        println!("Received registration from Sensor Agent: server_ip={}, package_id={}", sa_info.server_ip, sa_info.category);
        Ok(Response::new(Ack { success: true }))
    }
    
    type SendPackageFileStream = ReceiverStream<Result<FileChunk, Status>>;

    async fn send_package_file(
        &self,
        request: Request<PackageRequest>,
    ) -> Result<Response<Self::SendPackageFileStream>, Status> {
        let package_id = request.into_inner().category; // 获取包的 ID
    
        // 连接到 PostgreSQL 数据库
        let (client, connection) =
            tokio_postgres::connect("host=localhost port=5432 dbname=sensordb user=zxy password=123456", NoTls)
                .await
                .map_err(|e| Status::internal(format!("数据库连接失败: {}", e)))?;

        // 启动异步任务处理数据库连接
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("数据库连接错误: {}", e);
            }
        });

        // 查询数据库以获取包的信息
        let row = client.query_one(
            "SELECT path FROM deployment_packages WHERE id = $1",
            &[&package_id],
        )
        .await
        .map_err(|e| Status::internal(format!("数据库查询失败: {}", e)))?;
    
        let package_path: String = row.get("path");
        let install_script_path = "install.sh".to_string();
    
        // 准备发送的文件列表
        let files_to_send = vec![
            (package_path, "deb"),
            (install_script_path, "sh"),
        ];
    
        let (tx, rx) = mpsc::channel(4);
    
        // 启动任务来读取每个文件并发送数据块
        tokio::spawn(async move {
            for (file_path, file_type) in files_to_send {
                // 打开文件
                match TokioFile::open(&file_path).await {
                    Ok(file) => {
                        let mut reader = BufReader::new(file);
                        let mut buffer = [0u8; 1024];
    
                        // 读取文件并发送块
                        loop {
                            match reader.read(&mut buffer).await {
                                Ok(0) => break, // 文件结束
                                Ok(n) => {
                                    // 发送文件块
                                    let chunk = FileChunk {
                                        content: buffer[..n].to_vec(),
                                        file_type: file_type.to_string(),
                                    };
                                    if tx.send(Ok(chunk)).await.is_err() {
                                        eprintln!("发送文件块失败: {}", file_path);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("读取文件时出错: {} - {}", file_path, e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("无法打开文件: {} - {}", file_path, e);
                    }
                }
            }
        });
    
        // 从通道接收器创建 gRPC 流
        let stream = ReceiverStream::new(rx);
    
        // 返回带有流的响应
        Ok(Response::new(stream))
    }    
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // 将服务器地址改为实际的服务器内网 IP 地址和端口
    let addr = "192.168.31.145:3000".parse().unwrap();

    let sa_control = MySAControl::default();
    let sa_control = SaControlServer::new(sa_control);

    println!("SaControlServer listening on {}", addr);

    Server::builder()
        // GrpcWeb is over http1 so we must enable it.
        .accept_http1(true)
        .add_service(tonic_web::enable(sa_control))
        .serve(addr)
        .await?;

    Ok(())
}
