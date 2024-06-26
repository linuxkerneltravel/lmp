#  lmp vscode 插件使用指南

### 1. 运行效果

![](./images/lmp_vscode_ext.gif)

### 2. 相关提示

设置可视化面板存放路径

> 注意：别忘记面板路径后面加 "/"

![](./images/set_panel_addr.png)

面板命名必须遵循如下规则:

![](./images/panel_name.png)

若面板不存在，或路径，或名称不对，将出现如下错误提示：

![](./images/error_info.png)

### 3. 开发注意事项

1. yo code生成的框架，vscode最小版本是1.90，需要修改为1.74，不然我当前的版本。1.89无法运行插件
2. tsconfig

```json
{
  "compilerOptions": {
    "module": "commonjs",   // 不要用Node16，不然命令会触发失败
    "target": "ES2021",
    "lib": ["ES2021"],
    "sourceMap": true,
    "rootDir": "src",
    "strict": true /* enable all strict type-checking options */
    /* Additional Checks */
    // "noImplicitReturns": true, /* Report error when not all code paths in function return a value. */
    // "noFallthroughCasesInSwitch": true, /* Report errors for fallthrough cases in switch statement. */
    // "noUnusedParameters": true,  /* Report errors on unused parameters. */
  }
}
```



