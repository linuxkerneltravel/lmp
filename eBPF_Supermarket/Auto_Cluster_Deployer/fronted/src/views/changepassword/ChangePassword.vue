<template>
  <div class="change-password">
    <el-card class="change-password-card">
      <h2>修改密码</h2>
      <el-form :model="form" :rules="rules" label-position="left" label-width="80px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" id="username" autocomplete="off"></el-input>
        </el-form-item>
        
        <el-form-item label="当前密码" prop="old_password">
          <el-input
            v-model="form.old_password"
            :type="passwordType"
            id="old_password"
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
        
        <el-form-item label="新密码" prop="new_password">
          <el-input
            v-model="form.new_password"
            :type="passwordType"
            id="new_password"
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
          <el-button type="primary" @click="handleSubmit" :loading="loading">提交</el-button>
          <el-button @click="goBack">返回</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>
<script>
import axios from "axios";

export default {
  name: "ChangePasswordComponent",
  data() {
    return {
      form: {
        username: "",
        old_password: "",
        new_password: "",
      },
      loading: false,
      passwordType: "password", // 控制密码的显示和隐藏
    };
  },
  computed: {
    rules() {
      return {
        username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
        old_password: [{ required: true, message: '请输入当前密码', trigger: 'blur' }],
        new_password: [{ required: true, message: '请输入新密码', trigger: 'blur' }],
      };
    }
  },
  methods: {
    togglePasswordVisibility() {
      this.passwordType = this.passwordType === "password" ? "text" : "password";
    },
    async handleSubmit() {
      this.loading = true;
      try {
        const response = await axios.post("/api/change_password", {
          username: this.form.username,
          old_password: this.form.old_password,
          new_password: this.form.new_password
        });
        this.$message.success("密码修改成功");
        this.$router.push("/login");
      } catch (error) {
        if (error.response && error.response.status === 401) {
          this.$message.error('当前密码错误');
        } else {
          this.$message.error('修改失败，请重试');
        }
        console.error(error);
      } finally {
        this.loading = false;
      }
    },
    goBack() {
      this.$router.push("/home");
    }
  }
};
</script>
<style scoped>
.change-password-card {
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

.change-password {
  margin-top: 100px;
}
</style>
