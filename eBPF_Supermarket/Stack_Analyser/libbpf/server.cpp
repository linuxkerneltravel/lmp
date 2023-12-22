#include <cpprest/http_listener.h>
#include <cpprest/json.h>

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

void handle_post(http_request request) {
  request.extract_json().then([&request](json::value body) {
    // 处理收到的JSON数据
    // body 变量包含从客户端发送过来的JSON数据
    std::cout << body << std::endl;
    // 返回成功响应
    request.reply(status_codes::OK);
  }).wait();
}

int main() {
  http_listener listener("http://0.0.0.0:8080/data"); // 替换为你想要监听的URL
  listener.support(methods::POST, handle_post);

  try {
    listener.open().then([]() {
      // 服务器启动成功
    }).wait();

    std::cout << "Server running..." << std::endl;

    // 阻塞直到用户按下任意键退出程序
    std::cout << "Press Enter to exit..." << std::endl;
    std::string line;
    std::getline(std::cin, line);

    listener.close().then([]() {
      // 服务器关闭成功
    }).wait();
  } catch (std::exception const & e) {
    std::wcout << e.what() << std::endl;
  }

  return 0;
}
