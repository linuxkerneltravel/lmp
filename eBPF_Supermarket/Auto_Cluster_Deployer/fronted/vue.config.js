const { defineConfig } = require('@vue/cli-service');

module.exports = defineConfig({
  lintOnSave: false, // Disable linting

  // Enable proxy server
  devServer: {
    // The proxy server can forward specified route prefixes to the specified backend server
    proxy: {
      '/api': {
        target: 'http://xxx.xxx.xx.xx:8080',//主机ip地址
        ws: true, // Enable websockets
        changeOrigin: true, // Change the host header when proxying
        pathRewrite: {
          '^/api': '' // Replace '/api' with the target address
        }
      }
    }
  }
});
