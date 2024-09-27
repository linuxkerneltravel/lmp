<template>
  <div class="group-manage">
    <!-- 添加服务器到组的按钮，移到最左边并修改为天蓝色 -->
    <el-button type="primary" @click="openDialog" class="add-server-btn">添加服务器到组</el-button>

    <!-- 添加服务器的对话框 -->
    <el-dialog title="添加服务器到组" :visible.sync="dialogVisible">
      <el-form :model="addServerForm">
        <!-- 输入服务器IP地址 -->
        <el-form-item label="IP地址">
          <el-input
            v-model="addServerForm.ip_addresses"
            placeholder="输入服务器IP地址, 用逗号分隔多个IP"
          />
        </el-form-item>

        <!-- 选择服务器组 -->
        <el-form-item label="服务器组">
          <el-select v-model="addServerForm.group_description" placeholder="请选择服务器组">
            <el-option
              v-for="group in tableData"
              :key="group.id"
              :label="group.description"
              :value="group.description"
            />
          </el-select>
        </el-form-item>
      </el-form>

      <!-- 提交按钮 -->
      <div slot="footer" class="dialog-footer">
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="addServersToGroup">确定</el-button>
      </div>
    </el-dialog>

    <!-- 数据展示区域 -->
    <div>
      <el-table
        :data="tableData"
        stripe
        style="width: 100%"
        row-key="id"
      >
        <!-- 展开行，显示服务器列表 -->
        <el-table-column type="expand">
          <template v-slot="props">
            <el-table
              :data="props.row.servers"
              stripe
              style="width: 100%"
              class="nested-table"
            >

              <el-table-column label="操作" width="120">
                <template v-slot="serverProps">
                  <el-button
                    type="danger"
                    @click="removeServer(serverProps.row.ip_address, props.row.description)"
                  >
                    移除
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </template>
        </el-table-column>

        <el-table-column prop="id" label="ID" width="100"></el-table-column>
        <el-table-column
          prop="description"
          label="服务器组名"
          width="300"
        ></el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      tableData: [], // 存储服务器组数据
      dialogVisible: false, // 控制对话框显示
      addServerForm: {
        ip_addresses: '', // 存储输入的IP地址，支持多个
        group_description: '', // 存储选择的服务器组
      },
    };
  },
  created() {
    this.fetchGroups(); // 页面加载时自动获取服务器组数据
  },
  methods: {
    openDialog() {
      this.dialogVisible = true; // 打开对话框
    },
    async fetchGroups() {
      try {
        const response = await axios.get('/api/server_groups'); // 获取服务器组数据
        if (response.data.code === 200) {
          this.tableData = response.data.data.map(group => ({
            ...group,
            servers: null, // 初始化每个服务器组的 servers 属性
          }));
        } else {
          this.showErrorAlert('获取服务器组数据失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('请求服务器组数据时出错');
      }
    },
    async addServersToGroup() {
      // 提交数据到后端
      const payload = {
        ip_addresses: this.addServerForm.ip_addresses.split(',').map(ip => ip.trim()), // 分割多个IP地址
        group_description: this.addServerForm.group_description,
      };
      console.log('Payload to send:', payload); // 打印负载
      try {
        const response = await axios.post('/api/add_servers_to_group', payload); // 发送请求
        if (response.data.code === 200) {
          this.$message({
            message: '成功添加服务器到组',
            type: 'success',
          });
          this.dialogVisible = false; // 关闭对话框
          this.fetchGroups(); // 刷新数据
        } else {
          this.showErrorAlert(response.data.message);
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('添加服务器到组时出错');
      }
    },
    async removeServer(ipAddress, groupDescription) {
      const payload = {
        ip_addresses: [ipAddress], // 需要移除的服务器 IP 地址
        group_description: groupDescription, // 要从中移除服务器的组描述
      };

      try {
        const response = await axios.post('http://localhost:8080/remove_servers_from_group', payload); // 发送请求
        if (response.data.code === 200) {
          this.$message({
            message: '成功移除服务器',
            type: 'success',
          });
          this.fetchGroups(); // 刷新数据
        } else {
          this.showErrorAlert(response.data.message);
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('移除服务器时出错');
      }
    },
    showErrorAlert(message) {
      this.$alert(message, '错误', {
        confirmButtonText: '确定',
        type: 'error',
      });
    },
  },
};
</script>

<style scoped>
.group-manage {
  padding: 20px;
  display: flex;
  flex-direction: column;
}

/* 添加服务器按钮调整：移到最左边并改为天蓝色 */
.add-server-btn {
  align-self: flex-start;

  color: white;
}

/* 样式调整：让展开的服务器信息缩进 */
.nested-table {
  margin-left: 20px; /* 向右缩进 */
}

/* 样式调整：将字体设置为不加粗，字体变小且居中 */
.nested-column {
  font-weight: normal;
  font-size: 12px;
  text-align: center;
}
</style>
