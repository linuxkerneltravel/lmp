use sacontrol::{Empty, SaInfo, PackageRequest, IpRequest};
use sacontrol::sa_control_client::SaControlClient;
use tonic::Request;
use std::error::Error;
use std::time::Duration;
use tokio::time;
use tokio::process::Command;
use std::str;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use std::sync::Arc;
use serde::Deserialize;
use tokio::sync::Mutex;
use hyper_util::rt::TokioExecutor;
use tonic_web::GrpcWebClientLayer;
use tokio_stream::StreamExt;

pub mod sacontrol {
    tonic::include_proto!("sacontrol");
}

#[derive(Debug, Deserialize)]
struct Version {
    number: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    version: Version,
}

// 获取本机 IP 地址的异步辅助函数
async fn get_local_ip() -> Option<String> {
    let output = Command::new("hostname")
        .arg("-I")
        .output()
        .await.ok()?;

    let ip = String::from_utf8_lossy(&output.stdout)
        .trim()
        .split_whitespace()
        .next()?
        .to_string();

    Some(ip)
}

// 解析 deb 包中的版本号
async fn read_deb_version(file_path: &str) -> Result<String, Box<dyn Error>> {
    // 检查 deb 文件是否存在
    if fs::metadata(file_path).await.is_err() {
        println!("未找到 .deb 文件，使用默认版本 0.0");
        return Ok("0.0".to_string());
    }

    // 使用 dpkg-deb 命令提取版本信息
    let output = Command::new("dpkg-deb")
        .arg("-f")
        .arg(file_path)
        .arg("Version")
        .output()
        .await;  // 使用 await 等待命令执行完成

    match output {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            Ok(version.trim().to_string())
        }
        _ => {
            println!("无法读取 .deb 文件版本，使用默认版本 0.0");
            Ok("0.0".to_string())
        }
    }
}

// 解析配置文件并返回 PackageInfo
async fn check_current_version(config_path: &str) -> Result<String, Box<dyn Error>> {
    // 尝试读取配置文件内容
    let config_content = fs::read_to_string(config_path)
        .await
        .unwrap_or_else(|_| {
            // 打印错误信息
            println!("未找到配置文件，使用默认版本 0.0");
            "version = '0.0'".to_string()
        });

    println!("Task config file content: {:?}", config_content);

    // 尝试解析配置内容
    let config: Config = toml::from_str(&config_content)
        .unwrap_or_else(|err| {
            // 打印错误信息
            println!("Failed to parse task config: {}", err);
            // 返回默认版本号
            Config {
                version: Version {
                    number: "0.0".to_string(),
                },
            }
        });

    // 返回版本号
    Ok(config.version.number)
}


#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let svc = tower::ServiceBuilder::new()
        .layer(GrpcWebClientLayer::new())
        .service(client);

    let client = SaControlClient::with_origin(svc, "http://192.168.1.158:3000".try_into()?);
    let client = Arc::new(Mutex::new(client)); // 将 client 包装在 Arc<Mutex> 中

    // 预先检查 sudo 权限
    Command::new("sudo")
        .arg("-v")
        .output()
        .await?;

    // 循环处理版本检查和更新
    loop {
        let request = Request::new(Empty {});

        let response = {
            let mut client_guard = client.lock().await;
            client_guard.deploy_packages(request).await?
        };
        println!("Deploy_packages RESPONSE={:?}", response);

        // 获取本机 IP 地址
        let local_ip_str = get_local_ip().await.expect("Failed to get local IP address");

        // 创建 IpRequest 请求
        let request = Request::new(IpRequest { ip_address: local_ip_str.clone() });
        let response = {
            let mut client_guard = client.lock().await;
            client_guard.get_package_info_by_ip(request).await?
        };

        println!("Get_package_info_by_ip RESPONSE={:?}", response);

        let package_info = response.into_inner();
        
        // 如果 id 是 -1，则跳过后续操作，继续下一轮循环
        if package_info.id == -1 {
            println!("获取到的 id 为 -1，无需执行后续操作，继续下一轮循环。");
            continue;
        }

        let server_version = package_info.version;
        let category = package_info.id;

        // 获取代理信息
        let agent = SaInfo {
            server_ip: local_ip_str.clone(),
            category: category.clone(),
        };

        let client_clone = Arc::clone(&client); // 克隆 Arc 以在任务中共享

        // 注册代理
        let response = {
            let mut client_guard = client_clone.lock().await;
            client_guard.sa_regist(Request::new(agent)).await?
        };
        println!("SARegist RESPONSE={:?}", response);

        println!("服务器上的包版本: {}", server_version);

        // 获取本地版本
        let local_version = check_current_version("/usr/local/bin/config.toml").await?;

        println!("本地包版本: {}", local_version);

        // 比较本地版本与服务器版本
        if local_version < server_version {
            println!("本地版本较旧，检查接收到的 version 文件中的版本...");

            // 读取传输的 version 文件内容
            let transmitted_version = read_deb_version("package.deb").await?;

            println!("接收到的 deb 文件中的版本: {}", transmitted_version);

            // 比较接收到的 version 文件中的版本
            if transmitted_version < server_version {
                println!("接收到的版本文件版本较旧，准备请求更新包...");

                let request = Request::new(PackageRequest { category: category.clone() });
                let mut stream = {
                    let mut client_guard = client.lock().await;
                    client_guard.send_package_file(request).await?.into_inner()
                };

                // 创建文件保存接收到的更新包
                let mut file_deb = File::create("package.deb").await?;
                let mut file_sh = File::create("install.sh").await?;

                while let Some(file_chunk) = stream.next().await {
                    let file_chunk = file_chunk?;
                    let content = &file_chunk.content;

                    // 按文件类型保存内容
                    match file_chunk.file_type.as_str() {
                        "deb" => file_deb.write_all(content).await?,
                        "sh" => file_sh.write_all(content).await?,
                        _ => println!("未知的文件类型: {}", file_chunk.file_type),
                    }
                }

                println!("更新包已接收完毕，准备执行安装脚本...");

            } else {
                println!("传输的 deb 文件中的版本不小于服务器版本，无需更新。");
            }
        } else {
            println!("本地版本已是最新，无需更新。");
        }

        // 等待一段时间后再进行下一轮检查
        time::sleep(Duration::from_secs(5)).await;
    }
}
