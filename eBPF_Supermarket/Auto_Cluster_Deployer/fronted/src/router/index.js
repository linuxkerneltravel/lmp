import VueRouter from "vue-router";
import Cookies from "js-cookie";

// 引入组件
import Login from '../views/login/Login.vue';
import Register from '../views/register/Register.vue';
import Home from '../views/home/Home.vue';
import ServeManage from '../views/home/servemanage/ServeManage.vue';
import ServesManage from '../views/home/servesmanage/ServesManage.vue';
import DeploymentPackageManage from "../views/home/deploymentpackagemanage/DeploymentPackageManage.vue";
import DeploymentTaskManage from "../views/home/deploymenttaskmanage/DeploymentTaskManage.vue";
import ChangePassword from "../views/changepassword/ChangePassword.vue"
import ServerStatusOverview from "@/views/home/serverstatusoverview/ServerStatusOverview.vue";
// 创建路由实例
const router = new VueRouter({
  mode: 'history',
  routes: [
    {
      path: '/',
      redirect: '/login'
    },
    {
      path: '/login',
      component: Login
    },
    {
      path: '/register',
      component: Register
    },
    {
      path: '/change_password',
      component: ChangePassword
    },
    {
      path: '/home',
      component: Home,
      children: [
        {
          path: '',
          redirect: 'serves'
        },
        {
          path: 'serves',
          component: ServeManage
        },
        {
          path: 'server_groups',
          component: ServesManage
        },
        {
          path: 'deployment_packages',
          component: DeploymentPackageManage
        },
        {
          path: 'deployment_tasks',
          component: DeploymentTaskManage
        },
        {
          path: 'server_group_members',
          component: ServerStatusOverview
        },
      ]
    }
  ]
});

// 全局前置守卫
router.beforeEach((to, from, next) => {
  const token = Cookies.get('token'); // 获取存储的 token

  if (to.path === '/login' || to.path === '/register') {
    next(); // 登录或注册页面无需验证
  } else if (token) {
    next(); // 如果 token 存在，允许导航
  } else {
    next('/login'); // 否则重定向到登录页面
  }
});


export default router;
