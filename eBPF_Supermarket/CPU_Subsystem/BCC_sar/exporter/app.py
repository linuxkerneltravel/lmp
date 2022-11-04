from random import randint
from flask import Flask, request
import json

app = Flask(__name__)

@app.route("/")
def main_page():
    return """<h1>Welcome to explore Flask!</h1>
    <a href="/metrics">metrics</a>
    """

@app.route("/rolldice")
def roll_dice():
    return str(do_roll())

@app.route("/metrics")
def metrics():
    print(request.args)
    with open("metrics.json", "r") as f:
        metric_json = f.read()
    return metric_json

@app.route("/dns-cache")
def dns_cache():
    print(request.args)
    with open("dns-cache.json") as f:
        json_str = f.read()
    return json_str

def do_roll():
    return randint(1, 6)

app.run(host="0.0.0.0", port=7000, debug=True)