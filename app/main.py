from flask import Flask, render_template, request, redirect, url_for, flash
from colorama import Fore
import pymongo
import redis
import hashlib
import os
import dotenv
from time import sleep

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
        raise Exception(Fore.RED + "Failed to connect to MongoDB Atlas") from error


def connect_redis(number_of_tries=0):
    '''
    Connects to Redis

    Keyword Arguments: number_of_tries {Integer} -- The number of times the function has been called (default: {0})

    Raises: Exception -- If the function fails to connect to Redis

    Returns: None
    '''
    global REDIS_CLIENT
    REDIS_CLIENT = redis.Redis.from_url(
        f"rediss://{os.environ.get('REDIS_USERNAME')}:{os.environ.get('REDIS_PASSWORD')}@shi-redis-projectrexa.aivencloud.com:25156",  decode_responses=True)

    try:
        REDIS_CLIENT.ping()
        print(Fore.GREEN + "Connected to Redis")

    except Exception as error:
        if number_of_tries < 3:
            sleep(5*number_of_tries)
            connect_redis(number_of_tries + 1)
        raise Exception(Fore.RED + "Failed to connect to Redis") from error


# Flask App
app = Flask(__name__)
dotenv.load_dotenv()

# Database Connections
connect_mongodb()
connect_redis()




