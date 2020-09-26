CREATE TABLE `user` (
                        `id` bigint(20) NOT NULL AUTO_INCREMENT,                        // 自增的主键
                        `user_id` bigint(20) NOT NULL,                                  // 这里的 user_id 是单独创建的单独的bigint，之所以没有用自增是因为安全，不能让用户知道自己ID之后就可以知道有多少个用户了。
                                                                                        // 第二个原因是如果用户量很大，需要分库分表的时候，不同库里面的用户ID就有可能重复
                                                                                        // 所以这里的用户user_id要使用雪花算法，用一个分布式的ID生成器
                        `username` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
                        `password` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
                        `email` varchar(64) COLLATE utf8mb4_general_ci,
                        `gender` tinyint(4) NOT NULL DEFAULT '0',                       // 默认值是0
                        `create_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
                        `update_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

                        PRIMARY KEY (`id`),                                     // 给id建立一个主键
                        UNIQUE KEY `idx_username` (`username`) USING BTREE,     // 给username做了一个唯一的索引
                        UNIQUE KEY `idx_user_id` (`user_id`) USING BTREE        // 给userid做了一个唯一的索引
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
