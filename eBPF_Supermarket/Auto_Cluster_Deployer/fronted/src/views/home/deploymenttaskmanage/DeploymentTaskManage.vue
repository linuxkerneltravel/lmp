<template>
  <div class="task-manage">
    <!-- 头部区域：添加部署任务按钮和搜索框 -->
    <div class="header">
      <el-input v-model="searchText" placeholder="搜索任务" class="search-input" @input="filterTasks" />
      <el-button type="primary" @click="openAddTaskDialog">添加部署任务</el-button>
    </div>

    <!-- 数据展示区域：部署任务列表 -->
    <div>
      <el-table :data="filteredData" stripe style="width: 100%">
        <el-table-column prop="package_id" label="包ID" width="120"></el-table-column>
        <el-table-column prop="target_type" label="目标类型" width="150"></el-table-column>
        <el-table-column prop="target_id" label="目标ID" width="150"></el-table-column>
        <el-table-column label="操作" width="250">
          <template v-slot="scope">
            <el-button size="mini" type="danger" @click="confirmDelete(scope.row.package_id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 添加部署任务的弹窗 -->
    <el-dialog
      title="添加部署任务"
      :visible.sync="dialogVisible"
      width="40%"
      @close="resetAddTaskForm">
      <el-form :model="addTaskForm" :rules="rules" ref="addTaskForm">
        <el-form-item label="包ID" :label-width="formLabelWidth" prop="package_id">
          <el-input v-model.number="addTaskForm.package_id" placeholder="请输入包ID"></el-input>
        </el-form-item>
        <el-form-item label="目标类型" :label-width="formLabelWidth" prop="target_type">
          <el-select v-model="addTaskForm.target_type" placeholder="请选择目标类型" @change="handleTargetTypeChange">
            <el-option label="单个服务器" value="单台服务器"></el-option>
            <el-option label="服务器组" value="服务器组"></el-option>
            <el-option label="所有" value="所有"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="目标ID" :label-width="formLabelWidth" prop="target_id" v-if="showTargetId">
          <el-input v-model.number="addTaskForm.target_id" placeholder="请输入目标ID"></el-input>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="submitAddTaskForm">确定</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      tableData: [], // 表格数据
      filteredData: [], // 过滤后的数据
      dialogVisible: false, // 添加弹窗显示控制
      searchText: '', // 搜索框内容
      addTaskForm: {
        package_id: null,
        target_type: '',
        target_id: null
      }, // 添加表单数据
      showTargetId: true, // 控制目标ID字段的显示
      formLabelWidth: '100px', // 表单标签宽度
      rules: {
        package_id: [
          { required: true, message: '包ID不能为空', trigger: 'blur' },
          { type: 'number', message: '包ID必须为数字', trigger: 'blur' }
        ],
        target_type: [{ required: true, message: '目标类型不能为空', trigger: 'change' }],
        target_id: [
          { required: true, message: '目标ID不能为空', trigger: 'blur' },
          { type: 'number', message: '目标ID必须为数字', trigger: 'blur' }
        ]
      } // 表单验证规则
    };
  },
  created() {
    this.fetchTasks(); // 页面加载时获取所有部署任务
  },
  methods: {
    // 获取部署任务列表
    async fetchTasks() {
      const loading = this.$loading({ lock: true, text: '加载中...' });
      try {
        const response = await axios.get('/api/deployment_tasks');
        if (response.data.code === 200) {
          this.tableData = response.data.data;
          this.filteredData = this.tableData; // 初始化过滤数据
        } else {
          this.showErrorAlert('获取部署任务数据失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('请求部署任务数据时出错');
      } finally {
        loading.close(); // 关闭加载提示
      }
    },
    // 过滤部署任务
    filterTasks() {
      const search = this.searchText.toLowerCase();
      this.filteredData = this.tableData.filter(task =>
        task.package_id.toString().includes(search) ||
        task.target_type.toLowerCase().includes(search) ||
        (task.target_id && task.target_id.toString().includes(search))
      );
    },
    // 打开添加部署任务弹窗
    openAddTaskDialog() {
      this.dialogVisible = true;
    },
    // 提交表单
    submitAddTaskForm() {
      console.log('Submitting form with data:', this.addTaskForm); // 添加此行以调试
      this.$refs.addTaskForm.validate(async valid => {
        if (valid) {
          await this.addTask();
        } else {
          console.log('表单验证失败');
          return false;
        }
      });
    },
    // 添加部署任务
    async addTask() {
      console.log(JSON.stringify(this.addTaskForm));
      try {
        const payload = {
          package_id: this.addTaskForm.package_id,
          target_type: this.addTaskForm.target_type,
          target_id: this.addTaskForm.target_type !== 'All' ? this.addTaskForm.target_id : null
        };
        const response = await axios.post('/api/deployment_tasks', payload, {
          headers: {
            'Content-Type': 'application/json'
          }
        });
        if (response.data.code === 200) {
          this.tableData.push(response.data.data);
          this.filteredData = this.tableData; // 更新过滤后的数据
          this.dialogVisible = false;
          this.resetAddTaskForm();
          this.$message({
            type: 'success',
            message: '添加部署任务成功'
          });
        } else {
          this.showErrorAlert('添加部署任务失败');
        }
      } catch (error) {
        this.handleErrorResponse(error);
      }
    },
    // 确认删除部署任务
    confirmDelete(package_id) {
      this.$confirm('此操作将永久删除该部署任务, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      })
        .then(() => {
          this.deleteTask(package_id);
        })
        .catch(() => {
          this.$message({
            type: 'info',
            message: '已取消删除'
          });
        });
    },
    // 删除部署任务
    async deleteTask(package_id) {
      try {
        const response = await axios.delete(`/api/deployment_tasks/${package_id}`);
        if (response.data.code === 200) {
          this.tableData = this.tableData.filter(item => item.package_id !== package_id);
          this.filteredData = this.tableData; // 更新过滤后的数据
          this.$message({
            type: 'success',
            message: '删除成功'
          });
        } else {
          this.showErrorAlert('删除部署任务失败');
        }
      } catch (error) {
        this.handleErrorResponse(error);
      }
    },
    // 重置添加表单
    resetAddTaskForm() {
      this.$refs.addTaskForm.resetFields();
      this.addTaskForm.target_type = '';
      this.addTaskForm.target_id = null;
      this.showTargetId = true;
    },
    // 显示错误提示
    showErrorAlert(message) {
      this.$alert(message, '错误', {
        confirmButtonText: '确定',
        type: 'error'
      });
    },
    // 处理错误响应
    handleErrorResponse(error) {
      if (error.response) {
        this.showErrorAlert(`操作失败：${error.response.data.description || '未知错误'}`);
      } else if (error.request) {
        this.showErrorAlert('操作失败：服务器无响应');
      } else {
        this.showErrorAlert(`操作失败：${error.message}`);
      }
    },
    // 根据 target_type 控制 target_id 的显示
    handleTargetTypeChange(value) {
      if (value === 'All') {
        this.showTargetId = false;
        this.addTaskForm.target_id = null;
        this.$refs.addTaskForm.clearValidate(['target_id']);
      } else {
        this.showTargetId = true;
      }
    }
  }
};
</script>

<style scoped>
.task-manage {
  padding: 20px;
}
.header {
  margin-bottom: 20px;
  display: flex;
  justify-content: flex-start;
  align-items: center;
}
.header > .el-button {
  margin-left: 20px;
}
.search-input {
  margin-right: 20px;
  width: 300px;
}
</style>
