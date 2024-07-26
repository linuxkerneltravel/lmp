// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from "vscode";
import { startServer, restartServer, stopServer, TOKEN_SECRET } from "./server";
import { GrafanaEditorProvider } from "./editor";
import { install as installSourceMapSupport } from 'source-map-support';
import { sendTelemetry } from "./telemetry";
import { setVersion } from "./util";

import * as fs from 'fs'    // fzy: 为了检查面板文件是否存在


let default_panel_path = "/home/fzy/Desktop/panels/";  // fzy: 为了检查面板文件是否存在
let default_tool_config_file = "/home/fzy/lmp_tool_ext_config.json";
let sub_key = 0;   // 子系统计数，用于与element.label进行匹配


// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export async function activate(ctx: vscode.ExtensionContext) {

  setVersion(ctx.extension.packageJSON.version);
  startServer(ctx.secrets, ctx.extensionPath);

  ctx.subscriptions.push(GrafanaEditorProvider.register(ctx));

  ctx.subscriptions.push(
    vscode.commands.registerCommand(
      "grafana-vscode.openUrl",
      (uri: vscode.Uri) => {
        sendTelemetry(ctx);
        vscode.commands.executeCommand(
          "vscode.openWith",
          uri,
          GrafanaEditorProvider.viewType,
        );
      }),
  );
  // fzy
  // -------------------------------------------------------------------------------------
  TreeViewProvider.initTreeViewItem();
	ctx.subscriptions.push(vscode.commands.registerCommand('itemClick', (label) => {
    let file_path = default_panel_path + label + '.json';
    //console.log('file_path = ', file_path);
    if (fs.existsSync(file_path)) {
      let uri = vscode.Uri.file(file_path);
      // 获取label
      // 根据label确定uri
      //console.log('uri = ', uri);
      //console.log('lable = ', label);
        sendTelemetry(ctx);
        vscode.commands.executeCommand(
          "vscode.openWith",
          uri,
          GrafanaEditorProvider.viewType,
        );
    }
    else {
      let panel_search_info = label + " 可视化面板文件不存在，请检查！"
      vscode.window.showErrorMessage(panel_search_info);
    }
    
	}));
 // -------------------------------------------------------------------------------------

  vscode.workspace.onDidChangeConfiguration(async(event) => {
    if (event.affectsConfiguration("grafana-vscode.URL")) {
      restartServer(ctx.secrets, ctx.extensionPath);
    }
    // fzy, 让用户可以在设置中修改面板放置路径
    if (event.affectsConfiguration("grafana-vscode.default_panel_path")) {
      const settings = vscode.workspace.getConfiguration("grafana-vscode");
      
      default_panel_path = String(settings.get("default_panel_path"));
      //console.log("path = ", default_panel_path);
    }
    // fzy, 让用户可以在设置中修改json配置文件放置路径及配置文件名字
    if (event.affectsConfiguration("grafana-vscode.default_tool_config_file")) {
      const settings = vscode.workspace.getConfiguration("grafana-vscode"); 
      default_tool_config_file = String(settings.get("default_tool_config_file"));
       //console.log("file = ", default_tool_config_file);
       sub_key = 0; // 全局变量先清零，不然 subsystem无法匹配
       TreeViewProvider.initTreeViewItem();
    }
  });

  vscode.commands.registerCommand('grafana-vscode.setPassword', async () => {
    const passwordInput = await vscode.window.showInputBox({
      password: true,
      placeHolder: "My Grafana service account token",
      title: "Enter the service account token for your Grafana instance. This value will be stored securely in your operating system's secure key store."
    }) ?? '';
    await ctx.secrets.store(TOKEN_SECRET, passwordInput);
    restartServer(ctx.secrets, ctx.extensionPath);
  });

  installSourceMapSupport();
}

// This method is called when your extension is deactivated
export function deactivate() {
  stopServer();
}



// ---------------------------------------------------------------------------------
// fzy
import { CancellationToken, Event, ProviderResult, TreeDataProvider, TreeItem, TreeItemCollapsibleState, window} from "vscode";
import { json } from "stream/consumers";

// 扩展 TreeItem
/*
export class TreeItemNode extends TreeItem {
    constructor(
        public readonly label: string = '',
        public readonly collapsibleState: TreeItemCollapsibleState,
    ){
        super(label, collapsibleState);
    }

    command = {
        title: this.label,
        command: 'itemClick',
        tooltip: this.label,
        arguments: [
            this.label,
        ]
    };
    // 获取json文件路径
    // path = TreeItemNode.getPanelUrl(this.label);

    //static getPanelUrl(label: string):Uri {
    //    return Uri.file(join(__filename));
    //}
}
*/

export class TreeViewProvider implements TreeDataProvider<TreeItem> {

    onDidChangeTreeData?: Event<void | TreeItem | TreeItem[] | null | undefined> | undefined;

    getTreeItem(element: TreeItem): TreeItem | Thenable<TreeItem> {
        return element;
    }
    getChildren(element?: TreeItem | undefined): ProviderResult<TreeItem[]> {
        let jsonData: any; // 保存 json 数据
        jsonData = readLmpConfig();    // 读取json配置文件信息
        

        let arr: TreeItem[] = new Array();
          // treeview 根节点
        if (element == undefined) {
            for (const key in jsonData.subsystem_list) {
              let item: TreeItem = new TreeItem(jsonData.subsystem_list[key], TreeItemCollapsibleState.Expanded);
              item.description = jsonData.subsystem[key].description;
              arr.push(item);
            } 
            /*
            let item1: TreeItem = new TreeItem("CPU", TreeItemCollapsibleState.Expanded);
            item1.description = "Linux CPU子系统观测工具集";
            arr.push(item1);

            let item2: TreeItem = new TreeItem("network", TreeItemCollapsibleState.Expanded);
            item2.description = "Linux 网络子系统观测工具集";
            arr.push(item2);

            let item3: TreeItem = new TreeItem("memory", TreeItemCollapsibleState.Expanded);
            item3.description = "Linux 内存子系统观测工具集";
            arr.push(item3);

            let item4: TreeItem = new TreeItem("system_diagnosis", TreeItemCollapsibleState.Expanded);
            item4.description = "Linux 系统诊断工具集";
            arr.push(item4);

            let item5: TreeItem = new TreeItem("hypervisior", TreeItemCollapsibleState.Expanded);
            item5.description = "Linux 虚拟化子系统工具集";
            arr.push(item5);
            */

            return arr;
        } 
        // treeview 子节点
        else {
          //for (let sub_key = 0; sub_key <= 5; sub_key++) {
            if (element.label == jsonData.subsystem_list[sub_key]) { // 遍历所有子系统
              //console.log("jsonData.subsystem_list[key] = ", jsonData.subsystem_list[sub_key]);
              for (const tool_num in jsonData.subsystem[sub_key].tools) {  // 遍历子系统下的所有工具
                let tool_name = jsonData.subsystem[sub_key].tools[tool_num].name;
                let tool_description = jsonData.subsystem[sub_key].tools[tool_num].description;
                let item1:TreeItem = new TreeItem(tool_name, TreeItemCollapsibleState.None);
                item1.description = tool_description;
                let tool_command = {
                  title: tool_name,
                  command: 'itemClick',
                  tooltip: "点击将呈现工具的grafana可视化面板",
                  arguments: [
                    tool_name
                  ]
                }
                item1.command = tool_command;
                arr.push(item1);
              }
              sub_key++;   // key + 1, 匹配下一个子系统
              //console.log("sub_key = ", sub_key);
              return arr;
            }
            else {
              return null;
            }
      }
    }
          /*
           if (element.label == 'CPU') {
            // *****************************************************************************
            //let item1: TreeItem = new TreeItem("cpu_watcher", TreeItemCollapsibleState.None);
            let cpu_watcher_label = "cpu_watcher";
            let item1:TreeItem = new TreeItem(cpu_watcher_label, TreeItemCollapsibleState.None);
            item1.description = "cpu观测";
            let command_cpu_watcher = {
              title: cpu_watcher_label,
              command: 'itemClick',
              tooltip: "点击将呈现cpu_watcher的grafana的可视化面板",
              arguments: [
                cpu_watcher_label
              ]
            }
            item1.command = command_cpu_watcher;
            arr.push(item1);
            // *****************************************************************************
            let proc_iamge_label = "proc_image";
            let item2: TreeItem = new TreeItem(proc_iamge_label, TreeItemCollapsibleState.None);
            item2.description = "进程画像";
            let command_proc_image = {
              title: proc_iamge_label,
              command: 'itemClick',
              tooltip: "点击将呈现proc_image的grafana的可视化面板",
              arguments: [
                proc_iamge_label
              ]
            }
            item2.command = command_proc_image;
            arr.push(item2);
            // *****************************************************************************
            return arr;
           } 
           else if (element.label == 'network') {
            // *****************************************************************************
            let net_watcher_label = "net_watcher";
            let network_item1: TreeItem = new TreeItem(net_watcher_label, TreeItemCollapsibleState.None);
            network_item1.description = "网络观测";
            let command_net_watcher = {
              title: net_watcher_label,
              command: 'itemClick',
              tooltip: "点击将呈现net_watcher的grafana的可视化面板",
              arguments: [
                net_watcher_label
              ]
            }
            network_item1.command = command_net_watcher;
            arr.push(network_item1);
            // *****************************************************************************
            let net_manager_label = "net_manager";
            let network_item2: TreeItem = new TreeItem(net_manager_label, TreeItemCollapsibleState.None);
            network_item2.description = "网络管理";
            let command_net_manager = {
              title: net_manager_label,
              command: 'itemClick',
              tooltip: "点击将呈现net_manager的grafana的可视化面板",
              arguments: [
                net_manager_label
              ]
            }
            network_item2.command = command_net_manager;
            arr.push(network_item2);
            // *****************************************************************************
            return arr;
           }
           else if (element.label == 'memory') {
            let mem_watcher_label = "mem_watcher";
            let memory_item1: TreeItem = new TreeItem(mem_watcher_label, TreeItemCollapsibleState.None);
            memory_item1.description = "内存观测";
            let command_mem_watcher = {
              title: mem_watcher_label,
              command: 'itemClick',
              tooltip: "点击将呈现mem_watcher的grafana的可视化面板",
              arguments: [
                mem_watcher_label
              ]
            }
            memory_item1.command = command_mem_watcher;
            arr.push(memory_item1);

            return arr;
           }
           else if (element.label == 'system_diagnosis') {
            let stack_analyzer_label = "stack_analyzer";
            let system_diagnosis_item1: TreeItem = new TreeItem(stack_analyzer_label, TreeItemCollapsibleState.None);
            system_diagnosis_item1.description = "栈调用分析器";
            let command_stack_analyzer = {
              title: stack_analyzer_label,
              command: 'itemClick',
              tooltip: "点击将呈现stack_analyzer的grafana的可视化面板",
              arguments: [
                stack_analyzer_label
              ]
            }
            system_diagnosis_item1.command = command_stack_analyzer;
            arr.push(system_diagnosis_item1);

            return arr;
           }
           else if (element.label == 'hypervisior') {
            let kvm_watcher_label = "kvm_watcher";
            let hypervisior_item1: TreeItem = new TreeItem(kvm_watcher_label, TreeItemCollapsibleState.None);
            hypervisior_item1.description = "kvm虚拟化";
            let command_kvm_watcher = {
              title: kvm_watcher_label,
              command: 'itemClick',
              tooltip: "点击将呈现kvm_watcher的grafana的可视化面板",
              arguments: [
                kvm_watcher_label
              ]
            }
            hypervisior_item1.command = command_kvm_watcher;
            arr.push(hypervisior_item1);

            return arr;
           }
           else {
            return null;
           }
          
        }
    }
    */
    public static initTreeViewItem(){
        const treeViewProvider = new TreeViewProvider();
        window.registerTreeDataProvider('lmp_visualization.panel',treeViewProvider);
    }

}


export function readLmpConfig() {
  let data:any;
  if (fs.existsSync(default_tool_config_file)) //判断是否存在此文件
  {
    try {
      //读取文件内容，并转化为Json对象
      
      data = JSON.parse(fs.readFileSync(default_tool_config_file, "utf8"));
      // console.log(jsonData);
      //获取Json里key为data的数据
      //const data = userBugsJson['data'];  
    } 
    catch (error){
      console.error('Error parsing JSON:', error);
    }
  }
  else {
    console.error("no config file");
    let config_search_info =" json配置文件不存在,请检查！"
    vscode.window.showErrorMessage(config_search_info);
  }
  return data;    
}

// fzy end
// ---------------------------------------------------------------------------------

// backup
/**
 export class TreeViewProvider implements TreeDataProvider<TreeItemNode> {
    onDidChangeTreeData?: Event<void | TreeItemNode | TreeItem[] | null | undefined> | undefined;

    getTreeItem(element: TreeItemNode): TreeItem | Thenable<TreeItem> {
        return element;
    }
    getChildren(element?: TreeItem | undefined): ProviderResult<TreeItem[]> {
        let arr: TreeItem[] = new Array();
          // treeview 根节点
        if (element == undefined) {
            let item1: TreeItem = new TreeItem("CPU", TreeItemCollapsibleState.Expanded);
            item1.description = "Linux CPU子系统观测工具集";
            arr.push(item1);

            let item2: TreeItem = new TreeItem("network", TreeItemCollapsibleState.Expanded);
            item2.description = "Linux 网络子系统观测工具集";
            arr.push(item2);

            let item3: TreeItem = new TreeItem("memory", TreeItemCollapsibleState.Expanded);
            item3.description = "Linux 内存子系统观测工具集";
            arr.push(item3);

            let item4: TreeItem = new TreeItem("system_diagnosis", TreeItemCollapsibleState.Expanded);
            item4.description = "Linux 系统诊断工具集";
            arr.push(item4);

            let item5: TreeItem = new TreeItem("hypervisior", TreeItemCollapsibleState.Expanded);
            item5.description = "Linux 虚拟化子系统工具集";
            arr.push(item5);

            return arr;
        } 
        // treeview 子节点
        else {
           if (element.label == 'CPU') {
            //let item1: TreeItem = new TreeItem("cpu_watcher", TreeItemCollapsibleState.None);
            let item1:TreeItemNode = new TreeItemNode("cpu_watcher", TreeItemCollapsibleState.None);
            item1.description = "cpu观测";
            arr.push(item1);

            let item2: TreeItemNode = new TreeItemNode("proc_image", TreeItemCollapsibleState.None);
            item2.description = "进程画像";
            arr.push(item2);

            return arr;
           } 
           else if (element.label == 'network') {
            let network_item1: TreeItemNode = new TreeItemNode("net_watcher", TreeItemCollapsibleState.None);
            network_item1.description = "网络观测";
            
            //let command = {
            //title: 'net_watcher',
            //command: 'itemClick',
            //tooltip: "点击将呈现net_watcher的grafana的可视化面板",
            //arguments: [
            //]
            //}
            //network_item1.command = command;
            
            arr.push(network_item1);

            let network_item2: TreeItemNode = new TreeItemNode("net_manager", TreeItemCollapsibleState.None);
            network_item2.description = "网络管理";
            arr.push(network_item2);

            return arr;
           }
           else if (element.label == 'memory') {
            let memory_item1: TreeItemNode = new TreeItemNode("mem_watcher", TreeItemCollapsibleState.None);
            memory_item1.description = "内存观测";
            arr.push(memory_item1);

            return arr;
           }
           else if (element.label == 'system_diagnosis') {
            let system_diagnosis_item1: TreeItemNode = new TreeItemNode("stack_analyzer", TreeItemCollapsibleState.None);
            system_diagnosis_item1.description = "栈调用分析器";
            arr.push(system_diagnosis_item1);

            return arr;
           }
           else if (element.label == 'hypervisior') {
            let hypervisior_item1: TreeItemNode = new TreeItemNode("kvm_watcher", TreeItemCollapsibleState.None);
            hypervisior_item1.description = "kvm虚拟化";
            arr.push(hypervisior_item1);

            return arr;
           }
           else {
            return null;
           }
        }
    }
    public static initTreeViewItem(){
        const treeViewProvider = new TreeViewProvider();
        window.registerTreeDataProvider('lmp_visualization.panel',treeViewProvider);
    }

}
 */
