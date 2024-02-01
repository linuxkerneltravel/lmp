# 导入Frida模块
import frida

# 定义消息处理函数
def on_message(message, data):
    print("[on_message] message:", message, "data:", data)

# 附加到一个名为"cat"的进程
session = frida.attach("cat")

# 创建一个Frida脚本以枚举进程中的模块
script = session.create_script("""
rpc.exports.enumerateModules = () => {
  return Process.enumerateModules();
};
""")
# 为脚本绑定消息处理函数
script.on("message", on_message)
# 加载脚本
script.load()

# 打印当前进程中所有模块的名称
print([m["name"] for m in script.exports.enumerate_modules()])