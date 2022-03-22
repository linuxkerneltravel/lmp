<template>
  <div>
    <div class="gva-table-box">
      <!--     
      <div class="gva-btn-list">
        <el-button size="mini" type="primary" icon="plus" @click="openDialog">新增</el-button>
      </div>
      -->
      <el-table
        :data="tableData"
        style="width: 100%"
        tooltip-effect="dark"
      >
        <el-table-column type="selection" width="55" />
        <el-table-column align="left" label="插件名称" prop="pluginName" width="160" />
        <el-table-column align="left" label="插件说明" prop="intro" width="300" />
        <el-table-column align="left" label="插件类型" prop="typeText" width="100" />

        <el-table-column align="left" label="插件源码" width="120">
          <template #default="scope">
            <el-button type="text" size="mini" @click="openHelpDialog(scope.row)">查看</el-button>
          </template>
        </el-table-column>
        
        <el-table-column align="left" label="操作" min-width="160">
          <template #default="scope">
            <!-- 
            <el-popover v-model:visible="scope.row.visible" placement="top" width="200">
              <p>确定要删除吗？</p>
              <div style="text-align: right; margin-top: 8px;">
                <el-button size="mini" type="text" @click="scope.row.visible = false">取消</el-button>
                <el-button size="mini" type="primary" @click="deleteEbpfPlugin(scope.row)">确定</el-button>
              </div>
              <template #reference>
                <el-button type="text" size="mini">删除</el-button>
              </template>
            </el-popover>
            -->
            <el-popover v-model:visible="scope.row.visible" placement="top" width="200">
              <p>确定要操作吗？</p>
              <div style="text-align: right; margin-top: 8px;">
                <el-button size="mini" type="text" @click="scope.row.visible = false">取消</el-button>
                <el-button size="mini" type="primary" @click="handleExecPlugin(scope.row)">确定</el-button>
              </div>
              <template #reference>
                <el-button type="text" size="mini" v-if="scope.row.state==0">加载</el-button>
                <el-button type="text" size="mini" v-else>卸载</el-button>
              </template>
            </el-popover>            
          </template>
        </el-table-column>
      </el-table>
      <div class="gva-pagination">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :page-sizes="[10, 30, 50, 100]"
          :total="total"
          layout="total, sizes, prev, pager, next, jumper"
          @current-change="handleCurrentChange"
          @size-change="handleSizeChange"
        />
      </div>
    </div>
    <!--
    <el-dialog v-model="dialogFormVisible" :before-close="closeDialog" title="增加插件">
      <el-form :inline="true" :model="form" label-width="80px">
        <el-form-item label="插件名称">
          <el-input v-model="form.pluginName" autocomplete="off" />
        </el-form-item>
        <el-form-item label="插件路径">
          <el-input v-model="form.pluginPath" autocomplete="off" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="dialog-footer">
          <el-button size="small" @click="closeDialog">取 消</el-button>
          <el-button size="small" type="primary" @click="enterDialog">确 定</el-button>
        </div>
      </template>
    </el-dialog>
    -->
    <el-dialog v-model="dialogHelpVisible" 
      :before-close="closeHelpDialog" 
      width="95%" height="60%">
      <el-row>
        <el-col :span="12"><code-box codeType="python" :codeContent="pluginContent" /></el-col>
        <el-col :span="12"><display-plugin-doc :docURL="pluginDocURL" /></el-col>
      </el-row>
    </el-dialog>
  </div>
</template>

<script setup>
import {
  createExaEbpfPlugin,
  updateExaEbpfPlugin,
  deleteExaEbpfPlugin,
  getExaEbpfPlugin,
  getExaEbpfPluginList,
  LoadEbpfPlugins,
  UnloadEbpfPlugins,
  getExaEbpfPluginContent
} from '@/api/ebpfplugins'
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import displayPluginDoc from '@/view/ebpf/listplugins/displayPluginDoc.vue'
import CodeBox from '@/components/CodeBox/index.vue'

const form = ref({
  pluginName: '',
  pluginPath: '',
  pluginType: 0,
  intro: 'empty',
  state: 0
})

const page = ref(1)
const total = ref(0)
const pageSize = ref(10)
const tableData = ref([])

// 分页
const handleSizeChange = (val) => {
  pageSize.value = val
  getTableData()
}
const handleCurrentChange = (val) => {
  page.value = val
  getTableData()
}

// 查询
const getTableData = async() => {
  const table = await getExaEbpfPluginList({ page: page.value, pageSize: pageSize.value })
  if (table.code === 0) {
    table.data.list.forEach(function(element) { 
      switch(element.pluginType) {
        case 0:
          element.typeText = 'BCC'
          break;

      }
    });
    tableData.value = table.data.list
    total.value = table.data.total
    page.value = table.data.page
    pageSize.value = table.data.pageSize
    console.log('gettable')
    console.dir(table)
  }
}

getTableData()

// 显示插件帮助文档以及源代码
const dialogHelpVisible = ref(false)
const pluginContent = ref('')
const pluginDocURL = ref('docs/index.html')

const openHelpDialog = async(row) => {
  row.visible = false
  const res = await getExaEbpfPluginContent({ ID: row.ID })
  if (res.code === 0) {
    console.dir(res);
    pluginContent.value = res.data.ebpfPlugins.content;
    if (res.data.ebpfPlugins.docUrl != "")
      pluginDocURL.value = res.data.ebpfPlugins.docUrl;
    else 
      pluginDocURL.value = 'docs/index.html';
    console.dir(pluginDocURL);
    dialogHelpVisible.value = true;
  }
}
const closeHelpDialog = () => {
  dialogHelpVisible.value = false
}

// 创建/更新/删除插件
const dialogFormVisible = ref(false)
const type = ref('')

const openDialog = () => {
  type.value = 'create'
  dialogFormVisible.value = true
}
const enterDialog = async() => {
  let res
  switch (type.value) {
    case 'create':
      res = await createExaEbpfPlugin(form.value)
      break
    // case 'update':
    //   res = await updateExaEbpfPlugin(form.value)
    //   break
    default:
      res = await createExaEbpfPlugin(form.value)
      break
  }
  if (res.code === 0) {
    closeDialog()
    getTableData()
  }
}
const closeDialog = () => {
  dialogFormVisible.value = false
  form.value = {
    pluginName: '',
    pluginPath: '',
    pluginType: 0,
    intro: 'empty',
    state: 0
  }
}

// -const updateEbpfPlugin = async(row) => {
// -  const res = await getEbpfPlugin({ ID: row.ID })
// -  type.value = 'update'
// -  if (res.code === 0) {
// -    form.value = res.data.list
// -    dialogFormVisible.value = true
// -  }
// -}

const deleteEbpfPlugin = async(row) => {
  row.visible = false
  const res = await deleteExaEbpfPlugin({ ID: row.ID })
  if (res.code === 0) {
    ElMessage({
      type: 'success',
      message: '删除成功'
    })
    if (tableData.value.length === 1 && page.value > 1) {
      page.value--
    }
    getTableData()
  }
}

// 加载/卸载插件
const handleExecPlugin = async(row) => {
  row.visible = false
  let res = {};
  let optText = "";
  if (row.state == 0) {
    res = await LoadEbpfPlugins({ ID: row.ID })
    optText = '加载'
  } else {
    res = await UnloadEbpfPlugins({ ID: row.ID })
    optText = '卸载'
  }
  if (res.code === 0) {
    ElMessage({
      type: 'success',
      message: optText+'成功'
    })
    getTableData()
  }
}

</script>

<script>
export default {
  name: 'listPlugins'
}
</script>

<style></style>
