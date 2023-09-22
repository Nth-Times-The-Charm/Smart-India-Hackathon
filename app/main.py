import hashlib
import os
from time import sleep
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, send_from_directory
from flask_session import Session
from colorama import Fore
import pymongo
import redis
import dotenv


# Global Variables
MONGO_CLIENT = None
DB = None
REDIS_CLIENT = None

# Helper functions


def file_hash(file):
    '''
    Returns the hash of a file using SHA256

    Arguments: file {File} -- The file to be hashed

    Returns: String -- The hash of the file
    '''
    try:
        file.seek(0)
        while True:
            chunk = file.read(hashlib.sha256().block_size)
            if not chunk:
                break
            hashlib.sha256().update(chunk)
        return hashlib.sha256().hexdigest()
    except Exception as error:
        raise Exception(Fore.RED + f"Failed to hash file: {error}")


def connect_mongodb(number_of_tries=0):
    '''
    Connects to MongoDB Atlas

    Keyword Arguments: number_of_tries {Integer} -- The number of times the function has been called (default: {0})

    Raises: Exception -- If the function fails to connect to MongoDB Atlas

    Returns: None
    '''
    global MONGO_CLIENT, DB

    MONGO_CLIENT = pymongo.MongoClient(
        f"mongodb+srv://{os.environ.get('MONGODB_USERNAME')}:{os.environ.get('MONGODB_PASSWORD')}@shi-cluster.rqdq2aa.mongodb.net/?retryWrites=true&w=majority")
    DB = MONGO_CLIENT["certsecure"]

    try:
        MONGO_CLIENT.server_info()
        print(Fore.GREEN + "Connected to MongoDB Atlas")

    except Exception as error:
        if number_of_tries < 3:
            sleep(5*number_of_tries)
            connect_mongodb(number_of_tries + 1)
        raise Exception(
            Fore.RED + "Failed to connect to MongoDB Atlas") from error


def connect_redis(number_of_tries=0):
    '''
    Connects to Redis

    Keyword Arguments: number_of_tries {Integer} -- The number of times the function has been called (default: {0})

    Raises: Exception -- If the function fails to connect to Redis

    Returns: None
    '''
    global REDIS_CLIENT
    REDIS_CLIENT = redis.from_url(
        f"rediss://{os.environ.get('REDIS_USERNAME')}:{os.environ.get('REDIS_PASSWORD')}@shi-redis-projectrexa.aivencloud.com:25156")

    try:
        REDIS_CLIENT.ping()
        print(Fore.GREEN + "Connected to Redis")

    except Exception as error:
        if number_of_tries < 3:
            sleep(5*number_of_tries)
            connect_redis(number_of_tries + 1)
        raise Exception(Fore.RED + "Failed to connect to Redis") from error


# Flask App
app = Flask(__name__, static_url_path="/resources/public", static_folder="resources/public", template_folder="frontend/public")
dotenv.load_dotenv()
connect_mongodb()
connect_redis()

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_REDIS"] = REDIS_CLIENT
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_NAME"] = "X-Identity"
app.config["SESSION_COOKIE_PATH"] = "/"

Session(app)


@app.route("/", methods=["GET"])
def index():
    '''
    Renders the index page or redirects to the dashboard if the user is logged in

    Returns: HTML -- The index page or the dashboard page
    '''
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=7777)