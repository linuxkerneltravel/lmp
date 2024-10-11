<template>
  <div class="register">
    <el-card class="register-card">
      <h2>注册</h2>
      <el-form :model="form" :rules="rules" label-position="left" label-width="80px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" id="username" autocomplete="off"></el-input>
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="form.password"
            :type="passwordType"
            id="password"
            autocomplete="off"
          >
            <template #append>
              <el-button
                @click="togglePasswordVisibility"
                class="password-toggle"
                :icon="passwordType === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash'"
              ></el-button>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item label="确认密码" prop="confirmPassword">
          <el-input
            v-model="form.confirmPassword"
            :type="passwordType"
            id="confirmPassword"
            autocomplete="off"
          >
            <template #append>
              <el-button
                @click="togglePasswordVisibility"
                class="password-toggle"
                :icon="passwordType === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash'"
              ></el-button>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="register" :loading="loading">注册</el-button>
          <el-button @click="goBack">返回</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script>
import axios from "axios";

export default {
  name: "RegisterComponent",
  data() {
    return {
      form: {
        username: "",
        password: "",
        confirmPassword: "",
      },
      loading: false,
      passwordType: "password", // 控制密码的显示和隐藏
    };
  },
  computed: {
    rules() {
      return {
        username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
        password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
        confirmPassword: [
          { required: true, message: '请确认密码', trigger: 'blur' },
          { validator: this.validateConfirmPassword, trigger: 'blur' }
        ],
      };
    }
  },
  methods: {
    togglePasswordVisibility() {
      this.passwordType = this.passwordType === "password" ? "text" : "password";
    },
    validateConfirmPassword(rule, value, callback) {
      if (value !== this.form.password) {
        callback(new Error('密码与确认密码不匹配'));
      } else {
        callback();
      }
    },
    async register() {
      this.loading = true;
      try {
        const response = await axios.post(
          "api/register",
          {
            username: this.form.username,
            password: this.form.password,
          }
        );
        this.$message.success("注册成功");
        this.$router.push("/login");
      } catch (error) {
        this.$message.error("注册失败");
        console.error(error);
      } finally {
        this.loading = false;
      }
    },
    goBack() {
      this.$router.push("/login");
    },
  },
};
</script>

<style scoped>
.register-card {
  width: 400px;
  margin: 0 auto;
  padding: 20px;
}

.password-toggle {
  cursor: pointer;
  border: none;
  background: transparent;
  font-size: 18px;
  color: #409EFF;
}

.password-toggle:hover {
  color: #66b1ff;
}
.register{
  margin-top: 100px;
}
</style>
