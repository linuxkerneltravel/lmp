from flask import Flask
from flask_restful import Api,Resource,reqparse
from urllib import request
import requests,time,threading,werkzeug,os
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

app = Flask(__name__)
api = Api(app)

parser = reqparse.RequestParser()
parser.add_argument('bcc_file', type=FileStorage, location='files')
parser.add_argument('task')

#接收master传来的bcc文件，并保存在agent/bcc/目录下
#用postman测试传送文件ok,master节点发送文件时注意指定key='bcc_file'
class recv_file(Resource):
    def post(self):
        args = parser.parse_args()
        content = args.get('bcc_file')
        filename = secure_filename(content.filename)
        content.save(os.path.join(os.path.abspath('./bcc'),filename))
        return filename,201

#接收master传来的执行指令
#指令即为需要执行的bcc文件名
#多个文件名需用"-"隔开, task1-task2
class recv_task(Resource):
    def post(self):
        args = parser.parse_args()
        task = args.get('task')
        agent_path = os.path.join(os.path.abspath('.'),'agent.py')
        #执行 sudo /xx/xx/agent.py task
        if os.system("sudo %s %s" % (agent_path,task)):
            #return "sudo " + agent_path + ' ' + str(task)
            return 200
        else:
            return "执行失败"






#确认agent正常启动
class server_running(Resource):
    def get(self):
        return 200


api.add_resource(server_running,'/')
api.add_resource(recv_file,'/upload')
api.add_resource(recv_task,'/task')



#node服务注册回调
#当node上的app启动成功后会向master发送节点信息node_info
#其中Node_reg_api需要master节点实现
URL = "http://127.0.0.1:5000/"
Node_addr = "http://127.0.0.1"
Node_port = '5000'
Node_reg_api = 'http://127.0.0.1:7777/reg'
def test_reg_server():
    print('server starting...')
    while True:
        try:
            request.urlopen(url=URL)
            break
        except Exception as e:
            print(e)
            time.sleep(1)
    print('server started !')
    # server started callback
    agent_info = {'addr':Node_addr,'port':Node_port,'status':'running'}
    requests.post(Node_reg_api,json=agent_info)
 
if __name__ == '__main__':  
    threading.Thread(target=test_reg_server).start()
    app.run(debug=True)
