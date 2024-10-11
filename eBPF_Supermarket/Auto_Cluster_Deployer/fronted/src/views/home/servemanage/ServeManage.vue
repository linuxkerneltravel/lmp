<template>
  <div class="serve-manage">
    <!-- 搜索区域 -->
    <div class="header">
      <el-button type="primary" @click="openAddServerDialog">添加服务器</el-button>
    </div>

    <!-- 数据展示区域 -->
    <div>
      <el-table :data="tableData" stripe style="width: 100%">
        <el-table-column prop="id" label="ID" width="180"></el-table-column>
        <el-table-column prop="ip_address" label="IP地址" width="300"></el-table-column>
        <el-table-column label="操作">
          <template v-slot="scope">
            <el-button size="mini" type="danger" @click="confirmDelete(scope.row.ip_address)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 分页区域 -->
    <div>
      <!-- 这里可以添加分页的内容 -->
    </div>

    <!-- 添加服务器的弹窗 -->
    <el-dialog
      title="添加服务器"
      :visible.sync="dialogVisible"
      width="30%"
      @close="resetAddServerForm">
      <el-form :model="addServerForm">
        <el-form-item label="IP地址" :label-width="formLabelWidth">
          <el-input
            v-model="addServerForm.ip_address"
            @keyup.enter="addServer"
            placeholder="请输入IP地址">
          </el-input>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="addServer">确定</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      input: '',
      tableData: [],
      dialogVisible: false,
      addServerForm: {
        ip_address: ''
      },
      formLabelWidth: '80px'
    };
  },
  created() {
    this.fetchServers(); // 页面加载时自动查询所有服务器
  },
  methods: {
    async fetchServers() {
      try {
        const response = await axios.get('/api/servers'); // 替换为你的 API 端点
        if (response.data.code === 200) {
          this.tableData = response.data.data;
        } else {
          this.showErrorAlert('获取服务器数据失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('请求服务器数据时出错');
      }
    },
    openAddServerDialog() {
      this.dialogVisible = true; // 打开添加服务器的弹窗
    },
    async addServer() {
      // 校验 IP 地址格式
      if (!this.validateIpAddress(this.addServerForm.ip_address)) {
        this.showErrorAlert('请输入有效的 IP 地址');
        return;
      }

      // 检查 IP 地址是否重复
      if (this.isIpDuplicate(this.addServerForm.ip_address)) {
        this.showErrorAlert('该 IP 地址已存在');
        return;
      }

      // 发送添加请求到后端
      try {
        const response = await axios.post('/api/servers', { ip_address: this.addServerForm.ip_address }); // 替换为你的 API 端点
        if (response.data.code === 200) {
          this.tableData.push(response.data.data); // 添加返回的新服务器到表格
          this.dialogVisible = false; // 关闭弹窗
          this.resetAddServerForm(); // 重置表单
        } else {
          this.showErrorAlert('添加服务器失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('添加服务器时出错');
      }
    },
    resetAddServerForm() {
      this.addServerForm.ip_address = ''; // 重置添加服务器表单
    },
    showErrorAlert(message) {
      this.$alert(message, '错误', {
        confirmButtonText: '确定',
        type: 'error',
        callback: () => {
          console.log('用户确认了错误弹窗');
        }
      });
    },
    confirmDelete(ipAddress) {
      this.$confirm('此操作将永久删除该服务器, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      })
        .then(() => {
          this.deleteServer(ipAddress);
        })
        .catch(() => {
          this.$message({
            type: 'info',
            message: '已取消删除'
          });
        });
    },
    async deleteServer(ipAddress) {
      try {
        const response = await axios.delete(`/api/servers/${ipAddress}`); // 使用 IP 地址删除服务器
        if (response.data.code === 200) {
          this.tableData = this.tableData.filter(server => server.ip_address !== ipAddress); // 删除成功后更新表格数据
          this.$message({
            type: 'success',
            message: '删除成功'
          });
        } else {
          this.showErrorAlert('删除服务器失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('删除服务器时出错');
      }
    },
    validateIpAddress(ip) {
      // 正则表达式验证 IP 地址格式
      const ipPattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      return ipPattern.test(ip);
    },
    isIpDuplicate(ip) {
      // 检查输入的 IP 地址是否与现有的重复
      return this.tableData.some(server => server.ip_address === ip);
    }
  }
};
</script>

<style scoped>
.header {
  margin-bottom: 20px;
  display: flex;
}
.serve-manage {
  padding: 20px;
}
.header > .el-button {
  margin-right: 20px;
}
</style>
