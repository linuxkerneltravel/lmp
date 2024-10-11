<template>
  <div class="login">
    <el-card class="login-card">
      <div class="header">
        <h1>Sensor管理系统</h1>
      </div>
      <el-form :model="form" :rules="rules" ref="loginForm" label-position="left" label-width="80px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" id="username" autocomplete="off"></el-input>
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="form.password" type="password" id="password" autocomplete="off"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleLogin" :loading="loading">登录</el-button>
          <el-button @click="goToRegister">注册</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script>
import axios from "axios";
import Cookies from "js-cookie"; // 导入 js-cookie 库

export default {
  name: "LoginComponent",
  data() {
    return {
      form: {
        username: "",
        password: "",
      },
      loading: false,
    };
  },
  computed: {
    rules() {
      return {
        username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
        password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
      };
    }
  },
  methods: {
    handleLogin() {
      this.$refs.loginForm.validate(async (valid) => {
        if (valid) {
          this.loading = true;
          try {
          const response = await axios.post("/api/login", {
            username: this.form.username,
            password: this.form.password,
          });
          this.$message.success("登录成功");
          
          // 存储 token
          const token = response.data.token; // 假设 token 在响应数据中
          Cookies.set('token', token);

          // 跳转到首页
          this.$router.push('/home');
        } catch (error) {
          this.$message.error("登录失败");
          console.error(error);
        } finally {
          this.loading = false;
        }

        } else {
          this.$message.error("请填写所有必填字段");
        }
      });
    },
    goToRegister() {
      this.$router.push("/register");
    },
  },
};
</script>

<style scoped>
html, body {
  margin: 0;
  padding: 0;
  height: 100%;
}
.login-card {
  width: 400px;
  margin: 0 auto;
  padding: 20px;
}
.login {
  margin-top: 100px;
}
</style>
