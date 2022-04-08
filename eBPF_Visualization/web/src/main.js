import { createApp } from 'vue'
import 'element-plus/dist/index.css'
import './style/element_visiable.scss'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
// 引入gin-vue-admin前端初始化相关内容
import './core/gin-vue-admin'
// 引入封装的router
import router from '@/router/index'
import '@/permission'
import run from '@/core/gin-vue-admin.js'
import auth from '@/directive/auth'
import { store } from '@/pinia'
import App from './App.vue'
// 引入 Highlight.js
import 'highlight.js/lib/common';
// 引入 Highlight.js 的 Github 样式
import 'highlight.js/styles/github.css';
// 引入 Highlight.js 官方 Vue 插件
import hljsVuePlugin from "@highlightjs/vue-plugin";

const app = createApp(App)
app.config.productionTip = false

app
  .use(run)
  .use(store)
  .use(auth)
  .use(router)
  .use(ElementPlus, { locale: zhCn })
  .use(hljsVuePlugin)
  .mount('#app')

export default app
