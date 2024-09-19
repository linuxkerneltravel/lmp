# 数据库设计文档

## 1. 概述

本项目旨在实现一个自动化应用软件部署与管理系统，数据库设计以支持高效管理企业级 Linux 服务器集群的应用部署需求为目标。数据库的设计重点在于存储和管理服务器、服务器组、部署包及部署任务等核心信息，确保数据的一致性、可扩展性和高效查询性能。

数据库选用 **PostgreSQL** 作为后台存储系统，凭借其对复杂查询、大规模数据管理、多版本并发控制（MVCC）以及丰富的数据类型支持，适用于大规模企业运维环境。

## 2. 技术背景

本项目的数据库设计旨在支持以下关键功能：

- **用户管理**：系统用户的注册、登录与认证功能。
- **服务器管理**：管理服务器节点的状态、IP 地址等关键信息，并按服务器组分类。
- **软件包管理**：管理所有可部署的软件包及其版本，提供高效的软件版本控制与部署功能。
- **部署任务管理**：管理任务定义、调度与执行状态的跟踪，确保应用软件在指定服务器或服务器组中的自动化部署。

## 3. 数据库架构

数据库采用 **关系型模型**，通过外键、唯一性约束及索引确保数据一致性与高效查询。设计中包括以下核心实体：用户（`users`）、服务器（`servers`）、服务器组（`server_groups`）、部署包（`deployment_packages`）和部署任务（`deployment_tasks`）。

### 3.1 表结构设计

#### 3.1.1 用户表（`users`）

- 作用：存储系统用户的基本信息，确保用户认证和权限管理。

- 设计：

  ```sql
  CREATE TABLE users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
  );
  ```

  - `id`: 用户的唯一标识符。
  - `username`: 用户名，唯一且不可为空，确保用户注册时的唯一性。
  - `password_hash`: 密码的哈希值，确保安全存储用户密码。
  - `created_at` 和 `updated_at`: 用户信息创建和更新的时间戳，用于审计和管理。

#### 3.1.2 服务器表（`servers`）

- 作用：存储服务器节点的基本信息，如 IP 地址等，便于管理各个服务器的状态。

- 设计：

  ```sql
  CREATE TABLE servers (
      id SERIAL PRIMARY KEY,
      ip_address VARCHAR(15) NOT NULL UNIQUE
  );
  ```

  - `id`: 服务器的唯一标识符。
  - `ip_address`: 服务器的 IP 地址，唯一且不可为空，便于在网络中识别和管理。

#### 3.1.3 服务器组表（`server_groups`）

- 作用：对服务器进行逻辑分组，便于批量管理不同的业务或物理区域的服务器。

- 设计：

  ```sql
  CREATE TABLE server_groups (
      id SERIAL PRIMARY KEY,
      description TEXT
  );
  ```

  - `id`: 服务器组的唯一标识符。
  - `description`: 描述服务器组的用途或相关信息，便于理解组的功能。

#### 3.1.4 服务器组成员表（`server_group_members`）

- 作用：实现服务器与服务器组之间的一对多关系，记录每个服务器属于哪个服务器组。

- 设计：

  ```sql
  CREATE TABLE server_group_members (
      id SERIAL PRIMARY KEY,
      server_id INT NOT NULL,
      group_id INT NOT NULL,
      FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE,
      FOREIGN KEY (group_id) REFERENCES server_groups (id) ON DELETE CASCADE,
      UNIQUE (server_id, group_id)
  );
  ```

  - `server_id`: 引用 `servers` 表中的服务器 ID。
  - `group_id`: 引用 `server_groups` 表中的服务器组 ID。
  - **约束**：确保同一服务器不会被重复分配到同一服务器组中。

#### 3.1.5 部署包表（`deployment_packages`）

- 作用：管理软件包的版本信息、描述及路径，以便准确执行部署任务。

- 设计：

  ```sql
  CREATE TABLE deployment_packages (
      id SERIAL PRIMARY KEY,
      version VARCHAR(50) NOT NULL,
      software_name VARCHAR(100) NOT NULL,
      description TEXT,
      path VARCHAR(255) NOT NULL,
      UNIQUE (software_name, version)
  );
  ```

  - `version`: 软件包的版本号。
  - `software_name`: 软件包名称，唯一且不可为空。
  - `description`: 软件包的描述信息。
  - `path`: 软件包的存储路径，供部署时使用。
  - **唯一性约束**：确保同一软件的不同版本不会重复记录。

#### 3.1.6 部署任务表（`deployment_tasks`）

- 作用：记录各个部署任务的执行信息，包括目标服务器或服务器组，任务状态等。

- 设计：

  ```sql
  CREATE TABLE deployment_tasks (
      id SERIAL PRIMARY KEY,
      package_id INT NOT NULL,
      target_type VARCHAR(20) NOT NULL,
      target_id INT,
      is_deployed BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (package_id) REFERENCES deployment_packages (id) ON DELETE CASCADE,
      CHECK (target_type IN ('单台服务器', '服务器组', '所有')),
      UNIQUE (package_id, target_type, target_id)
  );
  ```

  - `package_id`: 外键，指向 `deployment_packages` 表中的软件包。
  - `target_type`: 部署目标类型（单台服务器、服务器组或所有服务器）。
  - `target_id`: 部署目标 ID，根据 `target_type` 的不同，引用 `servers` 表或 `server_groups` 表中的 ID。
  - **唯一性约束**：确保同一部署包不会重复部署到同一目标。
  - **检查约束**：确保 `target_type` 的合法性。

### 3.2 数据表之间的关系

- **`servers`** 与 **`server_groups`**：一对多关系，通过 **`server_group_members`** 实现服务器与服务器组的关联。
- **`deployment_packages`** 与 **`deployment_tasks`**：多对一关系，多个部署任务可以关联到同一个部署包。
- **`deployment_tasks`** 与 **`servers`** 或 **`server_groups`**：多对一关系，根据 `target_type` 确定部署任务的具体目标。

![dependent](../img/Dependency%20Diagram.png)

## 4. 约束与数据完整性

### 4.1 外键约束

所有涉及到表与表之间关系的字段均设置了 **外键约束**，确保数据引用的完整性。例如，`deployment_tasks` 表中的 `package_id` 外键确保了所有部署任务都与有效的软件包关联。

### 4.2 唯一性约束

关键字段如 `username`、`ip_address` 和 `software_name`+`version` 组合均设置了 **唯一性约束**，防止重复数据的插入，确保数据库的一致性。

### 4.3 检查约束

针对某些特定字段（如 `deployment_tasks` 中的 `target_type`）设置了 **检查约束**，确保字段值合法，防止插入无效数据。

## 5. 性能优化与索引策略

### 5.1 索引设计

为提升查询性能，在高频查询字段（如 `username`、`ip_address`）及外键字段上设置了索引，以加快查询和检索的速度。

### 5.2 批量插入与事务处理

通过 **事务处理** 确保批量操作的原子性，防止数据不一致的情况出现。对于大规模部署任务，使用事务来保证多个任务的创建和执行能够同时完成或回滚。

## 6. 安全性与备份机制

### 6.1 数据加密

用户的敏感信息（如 `password_hash`）经过哈希加密存储，避免明文密码暴露的安全风险。

### 6.2 备份与恢复

定期进行 **全量备份** 和 **增量备份**，确保数据库在发生故障时能够快速恢复。同时，日志记录支持数据库的**审计与恢复**操作。

## 7. 数据一致性与高可用性

数据库设计采用了 **MVCC（多版本并发控制）** 机制，确保多个事务并发执行时不会产生数据竞争。同时，通过主从数据库复制技术，提升数据库的高可用性，确保系统在高并发场景下的稳定运行。