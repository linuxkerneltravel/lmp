<template>
  <div class="package-manage">
    <!-- 头部区域：添加部署包按钮 -->
    <div class="header">
      <el-button type="primary" @click="openAddPackageDialog">添加部署包</el-button>
    </div>

    <!-- 数据展示区域：部署包列表 -->
    <div>
      <el-table :data="tableData" stripe style="width: 100%">
        <el-table-column prop="id" label="ID" width="100"></el-table-column>
        <el-table-column prop="software_name" label="软件名称" width="120"></el-table-column>
        <el-table-column prop="version" label="版本号" width="100"></el-table-column>
        <el-table-column prop="description" label="描述" width="300"></el-table-column>
        <el-table-column prop="path" label="路径" width="400"></el-table-column>
        <el-table-column label="操作" width="250">
          <template v-slot="scope">
            <!-- 编辑按钮 -->
            <el-button size="mini" type="primary" @click="openEditPackageDialog(scope.row)">编辑</el-button>
            <!-- 删除按钮 -->
            <el-button size="mini" type="danger" @click="confirmDelete(scope.row.software_name)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 添加部署包的弹窗 -->
    <el-dialog
      title="添加部署包"
      :visible.sync="dialogVisible"
      width="40%"
      @close="resetAddPackageForm">
      <el-form :model="addPackageForm">
        <el-form-item label="软件名称" :label-width="formLabelWidth">
          <el-input v-model="addPackageForm.software_name" placeholder="请输入软件名称"></el-input>
        </el-form-item>
        <el-form-item label="版本号" :label-width="formLabelWidth">
          <el-input v-model="addPackageForm.version" placeholder="请输入版本号"></el-input>
        </el-form-item>
        <el-form-item label="描述" :label-width="formLabelWidth">
          <el-input v-model="addPackageForm.description" placeholder="请输入描述"></el-input>
        </el-form-item>
        <el-form-item label="路径" :label-width="formLabelWidth">
          <el-input v-model="addPackageForm.path" placeholder="请输入部署包路径"></el-input>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="addPackage">确定</el-button>
      </div>
    </el-dialog>

    <!-- 编辑部署包的弹窗 -->
    <el-dialog
      title="编辑部署包"
      :visible.sync="editDialogVisible"
      width="40%"
      @close="resetEditPackageForm">
      <el-form :model="editPackageForm">
        <el-form-item label="软件名称" :label-width="formLabelWidth">
          <el-input v-model="editPackageForm.software_name" disabled></el-input>
        </el-form-item>
        <el-form-item label="版本号" :label-width="formLabelWidth">
          <el-input v-model="editPackageForm.version" placeholder="请输入版本号"></el-input>
        </el-form-item>
        <el-form-item label="描述" :label-width="formLabelWidth">
          <el-input v-model="editPackageForm.description" placeholder="请输入描述"></el-input>
        </el-form-item>
        <el-form-item label="路径" :label-width="formLabelWidth">
          <el-input v-model="editPackageForm.path" placeholder="请输入部署包路径"></el-input>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="editDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="updatePackage">保存</el-button>
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
      dialogVisible: false, // 添加弹窗显示控制
      editDialogVisible: false, // 编辑弹窗显示控制
      addPackageForm: {
        software_name: '',
        version: '',
        description: '',
        path: ''
      }, // 添加表单数据
      editPackageForm: {
        software_name: '',
        version: '',
        description: '',
        path: ''
      }, // 编辑表单数据
      formLabelWidth: '100px' // 表单标签宽度
    };
  },
  created() {
    this.fetchPackages(); // 页面加载时获取所有部署包
  },
  methods: {
    // 获取部署包列表
    async fetchPackages() {
      try {
        const response = await axios.get('/api/deployment_packages');
        if (response.data.code === 200) {
          this.tableData = response.data.data;
        } else {
          this.showErrorAlert('获取部署包数据失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('请求部署包数据时出错');
      }
    },
    // 打开添加部署包弹窗
    openAddPackageDialog() {
      this.dialogVisible = true;
    },
    // 打开编辑部署包弹窗
    openEditPackageDialog(packageData) {
      this.editPackageForm = { ...packageData };
      this.editDialogVisible = true;
    },
    // 添加部署包
    async addPackage() {
      if (!this.addPackageForm.software_name || !this.addPackageForm.version || !this.addPackageForm.path) {
        this.showErrorAlert('请完整填写表单');
        return;
      }

      try {
        const response = await axios.post('/api/deployment_packages', this.addPackageForm);
        if (response.data.code === 200) {
          this.tableData.push(response.data.data);
          this.dialogVisible = false;
          this.resetAddPackageForm();
        } else {
          this.showErrorAlert('添加部署包失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('添加部署包时出错');
      }
    },
    // 修改部署包
    async updatePackage() {
      try {
        const response = await axios.put(`/api/deployment_packages/${this.editPackageForm.software_name}`, this.editPackageForm);
        if (response.data.code === 200) {
          // 更新表格数据
          const index = this.tableData.findIndex(item => item.software_name === this.editPackageForm.software_name);
          if (index !== -1) {
            this.tableData.splice(index, 1, response.data.data);
          }
          this.editDialogVisible = false;
          this.resetEditPackageForm();
        } else {
          this.showErrorAlert('更新部署包失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('更新部署包时出错');
      }
    },
    // 重置添加表单
    resetAddPackageForm() {
      this.addPackageForm = {
        software_name: '',
        version: '',
        description: '',
        path: ''
      };
    },
    // 重置编辑表单
    resetEditPackageForm() {
      this.editPackageForm = {
        software_name: '',
        version: '',
        description: '',
        path: ''
      };
    },
    // 确认删除部署包
    confirmDelete(software_name) {
      this.$confirm('此操作将永久删除该部署包, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      })
        .then(() => {
          this.deletePackage(software_name);
        })
        .catch(() => {
          this.$message({
            type: 'info',
            message: '已取消删除'
          });
        });
    },
    // 删除部署包
    async deletePackage(software_name) {
      try {
        const response = await axios.delete(`/api/deployment_packages/${software_name}`);
        if (response.data.code === 200) {
          this.tableData = this.tableData.filter(item => item.software_name !== software_name);
          this.$message({
            type: 'success',
            message: '删除成功'
          });
        } else {
          this.showErrorAlert('删除部署包失败');
        }
      } catch (error) {
        console.error(error);
        this.showErrorAlert('删除部署包时出错');
      }
    },
    // 显示错误提示
    showErrorAlert(message) {
      this.$alert(message, '错误', {
        confirmButtonText: '确定',
        type: 'error'
      });
    }
  }
};
</script>

<style scoped>
.package-manage {
  padding: 20px;
}
.header {
  margin-bottom: 20px;
  display: flex;
  justify-content: flex-start;
}
.header > .el-button {
  margin-right: 10px;
}
</style>
