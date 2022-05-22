import base64
import flask
from flask import request, jsonify
import sys
import uuid
import requests

TA_IP = 'localhost'
TA_PORT = 5000

Id = uuid.uuid4()
port = 8080
if len(sys.argv) > 1:
    port = int(sys.argv[1])
host = 'localhost'
if len(sys.argv) > 2:
    host = sys.argv[2]
data = { 'host': host, 'port': port, 'nodeId': str(Id) }
response = requests.post('http://' + TA_IP + ':' + str(TA_PORT) + '/worker-nodes', json = data)
print(response.text)


app = flask.Flask(__name__)
app.config["DEBUG"] = False

@app.route('/test', methods=['GET'])
def test():
    return True

app.run(port=port)