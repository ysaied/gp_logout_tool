#!/usr/bin/python3
import datetime
import os.path
from jinja2 import Environment, FileSystemLoader
from flask import Flask, render_template

log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)

uri = datetime.datetime.now().strftime("%Y%m%d%H%M")
time_now = datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S")

def html_page(gp_duplicate_lst, gp_duplicate_ext):
    parameters = {
        "page_title": "GP-Logout-Tool",
        "page_heading": "Global Protect Logout Duplicate Sessions",
        "time_now" : time_now,
        "users_lst": gp_duplicate_lst,
        "users_ext" : gp_duplicate_ext
    }
    fileLoader = FileSystemLoader("templates")
    env_jinja2 = Environment(loader=fileLoader)
    temp_jinja2 = env_jinja2.get_template("report.html")

    rend_jinja2 = temp_jinja2.render(parameters)

    if not os.path.exists("./site"):
        os.mkdir("./site")

    report_html = f"{uri}.html"
    with open(f"./site/{report_html}", "w") as index_file:
        index_file.write(rend_jinja2)

    log4y(f"HTML Portal: WEB page http://127.0.0.1:8000/{uri} is generated")

def main_page():
    files = os.listdir("./site")
    files = sorted(files)
    parameters = {
        "page_title": "GP-Logout-Tool",
        "http_server" : "http://127.0.0.1:8000",
        "files" : files
    }
    fileLoader = FileSystemLoader("templates")
    env_jinja2 = Environment(loader=fileLoader)
    temp_jinja2 = env_jinja2.get_template("index.html")
    rend_jinja2 = temp_jinja2.render(parameters)

    index_html = f"index.html"
    with open(f"./site/{index_html}", "w") as index_file:
        index_file.write(rend_jinja2)


app = Flask(__name__, template_folder="./site", static_folder="./site")

@app.route("/")
def index():
    main_page()
    return render_template(f"index.html")

@app.route("/favicon.ico")
def icon():
    return "icon"

@app.route("/<id>")
def report(id):
    return render_template(f"{id}.html")

if __name__ == '__main__':
    app.run(port=8000)
