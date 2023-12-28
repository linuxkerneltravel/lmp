#include <cpprest/http_client.h>
#include <cpprest/json.h>

using namespace web;
using namespace web::http;
using namespace web::http::client;

int main() {
  utility::string_t url = U("http://0.0.0.0:8080/data"); // 替换为你的API URL

  http_client client(url);

  json::value postData;
  postData[U("key")] = json::value::string(U("value")); // 替换为你要发送的数据

  http_request request(methods::POST);
  request.headers().set_content_type(U("application/json"));
  request.set_body(postData);

  client.request(request).then([](http_response response) {
    if (response.status_code() == status_codes::OK) {
      // 处理成功响应
      // response.extract_json() 可以用于处理响应的JSON数据
    } else {
      // 处理错误响应
    }
  }).wait();

  return 0;
}
