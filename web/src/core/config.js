/**
 * 网站配置文件
 */

const config = {
  appName: 'Linux Microscope',
  appLogo: 'http://lmp.kerneltravel.net/images/logo/LMP-logo.png',
  showViteLogo: true
}

export const viteLogo = (env) => {
  if (config.showViteLogo) {
    const chalk = require('chalk')
    console.log(
      chalk.green(
        `> 欢迎使用 LMP。`
      )
    )
    console.log('\n')
  }
}

export default config
