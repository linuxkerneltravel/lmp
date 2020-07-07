#该服务是模拟go master节点，测试用。

from flask import Flask
from flask_restful import Api,Resource,reqparse
from urllib import request
import requests,time

app = Flask(__name__)
api = Api(app)

#目前规划是在go master中应当记录活跃接点的信息
parser = reqparse.RequestParser()
parser.add_argument('addr', type=str)
parser.add_argument('port', type=str)
parser.add_argument('status', type=str)

#模拟的master节点上的node服务注册接口
#node节点在启动服务后会向该接口发送json格式的node_info信息
#包含node的ip地址:addr,端口号：port和状态:status
class reg(Resource):
    def post(self):
        args  = parser.parse_args()
        print(args)
        #activate_node.add(args)
        return args,200


api.add_resource(reg,'/reg')


if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=7777)
