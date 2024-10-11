<template>
  <div class="group-manage">
    <!-- 搜索区域 -->
    <div class="header">
      <el-input
        v-model="search"
        placeholder="搜索服务器组"
        prefix-icon="el-icon-search"
        class="search-input"
      />
      <el-button type="primary" @click="openAddGroupDialog">添加服务器组</el-button>
    </div>

    <!-- 数据展示区域 -->
    <div>
      <el-table :data="filteredTableData" stripe style="width: 100%">
        <el-table-column prop="id" label="ID" width="100"></el-table-column>
        <el-table-column prop="description" label="服务器组名" width="300"></el-table-column>
        <el-table-column label="操作">
          <template v-slot="scope">
            <el-button size="mini" type="danger" @click="confirmDelete(scope.row.id)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 添加服务器组的弹窗 -->
    <el-dialog
      title="添加服务器组"
      :visible.sync="dialogVisible"
      width="30%"
      @close="resetAddGroupForm">
      <el-form :model="addGroupForm">
        <el-form-item label="描述" :label-width="formLabelWidth">
          <el-input
            v-model="addGroupForm.description"
            @keyup.enter="addGroup"
            placeholder="请输入服务器组描述">
          </el-input>
        </el-form-item>
      </el-form>
      <template v-slot:footer>
        <div class="dialog-footer">
          <el-button @click="dialogVisible = false">取消</el-button>
          <el-button type="primary" @click="addGroup">确定</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      tableData: [], // 存储服务器组数据
      dialogVisible: false, // 弹窗可见性
      addGroupForm: {
        description: '', // 添加服务器组的表单
      },
      formLabelWidth: '80px', // 表单标签宽度
      search: '', // 搜索框内容
    };
  },
  computed: {
    filteredTableData() {
      return this.tableData.filter(group => 
        group.description.toLowerCase().includes(this.search.toLowerCase())
      );
    }
  },
  created() {
    this.fetchGroups(); // 页面加载时自动获取服务器组数据
  },
  methods: {
    async fetchGroups() {
      try {
        const response = await axios.get('/api/server_groups'); // 调用获取服务器组数据的 API
        if (response.data.code === 200) {
          this.tableData = response.data.data;
        } else {
          this.showErrorAlert('获取服务器组数据失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('请求服务器组数据时出错');
      }
    },
    openAddGroupDialog() {
      this.dialogVisible = true; // 打开添加服务器组的弹窗
    },
    async addGroup() {
      if (!this.addGroupForm.description.trim()) {
        this.showErrorAlert('请输入有效的描述');
        return;
      }

      try {
        const response = await axios.post('/api/server_groups', { description: this.addGroupForm.description }); // 发送添加服务器组请求
        if (response.data.code === 200) {
          this.tableData.push(response.data.data); // 将新服务器组添加到表格
          this.dialogVisible = false; // 关闭弹窗
          this.resetAddGroupForm(); // 重置表单
        } else {
          this.showErrorAlert('添加服务器组失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('添加服务器组时出错');
      }
    },
    resetAddGroupForm() {
      this.addGroupForm.description = ''; // 重置添加服务器组表单
    },
    showErrorAlert(message) {
      this.$alert(message, '错误', {
        confirmButtonText: '确定',
        type: 'error',
      });
    },
    confirmDelete(groupId) {
      this.$confirm('此操作将永久删除该服务器组, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      })
        .then(() => {
          this.deleteGroup(groupId);
        })
        .catch(() => {
          this.$message({
            type: 'info',
            message: '已取消删除'
          });
        });
    },
    async deleteGroup(groupId) {
      try {
        const response = await axios.delete(`/api/server_groups/${groupId}`); // 删除服务器组请求
        if (response.data.code === 200) {
          this.tableData = this.tableData.filter(group => group.id !== groupId); // 删除成功后更新表格数据
          this.$message({
            type: 'success',
            message: '删除成功'
          });
        } else {
          this.showErrorAlert('删除服务器组失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('删除服务器组时出错');
      }
    }
  }
};
</script>

<style scoped>
.header {
  margin-bottom: 20px;
  display: flex;
  align-items: center;
}

.search-input {
  margin-right: 20px;
  width: 300px;
}

.group-manage {
  padding: 20px;
}

.dialog-footer {
  text-align: right;
}

.el-button--primary {
  background-color: #409EFF;
  border-color: #409EFF;
}
.el-button--danger {
  background-color: #f56c6c;
  border-color: #f56c6c;
}
</style>
