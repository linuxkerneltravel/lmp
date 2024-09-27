<template>
  <el-container class="home-container">
    <!-- 头部区域 -->
    <el-header>
      <div class="header-left">
        <!-- <img src="" alt="" class="logo"> -->
        <span>服务器部署管理系统</span>
      </div>
      <!-- 头像和下拉菜单 -->
      <el-dropdown @command="handleCommand">
        <el-avatar class="avatar">
          <i class="el-icon-user"></i> <!-- 使用 Element 的图标 -->
        </el-avatar>
        <el-dropdown-menu slot="dropdown">
          <el-dropdown-item command="change-password">修改密码</el-dropdown-item>
          <el-dropdown-item command="logout">退出登录</el-dropdown-item>
        </el-dropdown-menu>
      </el-dropdown>
    </el-header>
    <!-- 页面主体 -->
    <el-container>
      <!-- 侧边栏 -->
      <el-aside width="200px" class="aside-menu">
        <el-menu
          :default-active="this.$route.path"
          background-color="#333744"
          text-color="#fff"
          router
          active-text-color="#ffd04b"
          class="el-menu-custom"
          @open="handleOpen"
          @close="handleClose">
          <!-- 服务器管理 -->
          <el-menu-item index="/home/serves">
            <span style="font-size: 20px;">服务器管理</span>
          </el-menu-item>

          <!-- 服务器组管理 -->
          <el-menu-item index="/home/server_groups">
            <span style="font-size: 20px;">服务器组管理</span>
          </el-menu-item>

          <!-- 部署包管理 -->
          <el-menu-item index="/home/deployment_packages">
            <span style="font-size: 20px;">部署包管理</span>
          </el-menu-item>

          <!-- 部署任务管理 -->
          <el-menu-item index="/home/deployment_tasks">
            <span style="font-size: 20px;">部署任务管理</span>
          </el-menu-item>

          <!-- 服务器状态总览 -->
          <el-menu-item index="/home/server_group_members">
            <span style="font-size: 20px;">服务器状态总览</span>
          </el-menu-item>
        </el-menu>
      </el-aside>
      <!-- 右侧内容主体 -->
      <el-main>
        <router-view></router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script>
export default {
  name: 'Home',
  data() {
    return {
      activeIndex: this.$route.path
    }
  },
  watch: {
    $route(to) {
      this.activeIndex = to.path;
    }
  },
  methods: {
    handleCommand(command) {
      if (command === 'logout') {
        this.logout();
      } else if (command === 'change-password') {
        this.$router.push('/change_password');
      }
    },
    logout() {
      this.$router.push('/login');
    },
    handleOpen(key, keyPath) {
      console.log(key, keyPath);
    },
    handleClose(key, keyPath) {
      console.log(key, keyPath);
    }
  }
}
</script>

<style scoped>
.home-container {
  height: 100vh;
}
.el-header {
  background-color: #373D41;
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: #fff;
  font-size: 28px;
  padding: 0 20px;
}
.header-left {
  display: flex;
  align-items: center;
}
.logo {
  width: 40px;
  height: 40px;
  margin-right: 15px;
}
.avatar {
  cursor: pointer;
}
.el-aside {
  background-color: #333744;
  padding: 0;
}
.el-main {
  background-color: #EAEDF1;
}
.el-menu-custom {
  border-right: none; /* 移除右边框 */
}

/* 一级菜单项左对齐 */
.el-menu-custom .el-submenu__title {
  padding-left: 0; /* 移除内边距 */
  margin-left: 0; /* 移除左侧间距 */
  display: flex; /* 使用 Flex 布局 */
  align-items: center; /* 垂直居中对齐 */
}

/* 二级菜单项的缩进 */
.el-menu-custom .el-menu-item {
  padding-left: 30px; /* 二级菜单缩进 */
}

/* 激活状态的背景色和字体颜色 */
.el-menu-custom .el-menu-item.is-active {
  background-color: #ffd04b; /* 激活时背景色 */
  color: #333744; /* 激活时字体颜色 */
}

/* 鼠标悬停的背景色 */
.el-menu-custom .el-menu-item:hover {
  background-color: #4a4a4a; /* 鼠标悬停时背景色 */
  color: #fff; /* 鼠标悬停时字体颜色 */
}
</style>
