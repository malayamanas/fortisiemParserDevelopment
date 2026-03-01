import os
from flask import Flask, render_template

app = Flask(__name__, template_folder="parser_studio/templates",
            static_folder="parser_studio/static")

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
