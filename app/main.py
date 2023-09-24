import hashlib
import secrets
import os
import time
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, send_from_directory
from flask_session import Session
from colorama import Fore
import pymongo
import redis
import dotenv
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException


# Global Variables
MONGO_CLIENT = None
DB = None
REDIS_CLIENT = None


# Flask App

app = Flask(__name__, static_url_path="/resources/public",
            static_folder="resources/public", template_folder="frontend")

# Database Connections


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
            time.sleep(5*number_of_tries)
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
            time.sleep(5*number_of_tries)
            connect_redis(number_of_tries + 1)
        raise Exception(Fore.RED + "Failed to connect to Redis") from error


connect_mongodb()
connect_redis()

# Flask Config


dotenv.load_dotenv()
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = os.environ.get("SENDINBLUE_API_KEY")

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

# Helper Functions


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


def send_email(email, name, type, verification_code=None):
    '''
    Sends an email to the user

    Arguments: email {String} -- The email of the user
               type {String} -- The type of email to be sent

    Keyword Arguments: verification_code {String} -- The verification code to be sent (default: {None})

    Raises: Exception -- If the function fails to send the email

    Returns: None
    '''
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration))

    match type:
        case "organization_verification":
            subject = "Organization Verification - CertSecure"
            sender = {"name": "CertSecure",
                      "email": "noreply@projectrexa.dedyn.io"}
            to = [{"email": email, "name": name}]
            reply_to = {"email": "certsecure@projectrexa.dedyn.io",
                        "name": "CertSecure"}
            html = render_template(
                'email/sign-up.html', name=name, link="https://certsecure.project.projectrexa.dedyn.io/organization/verify-domain?verification-code="+verification_code, year=time.strftime("%Y"))
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=to, html_content=html, reply_to=reply_to, sender=sender, subject=subject)

        case _:
            return False
    try:
        api_instance.send_transac_email(send_smtp_email)
        return True
    except ApiException as e:

        return False


# Flask Routes


@app.route("/", methods=["GET"])
def index():
    '''
    Renders the index page or redirects to the dashboard if the user is logged in

    Returns: HTML -- The index page or the dashboard page
    '''
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    '''
    Renders the dashboard page if the user is logged in or redirects to the login page

    Returns: HTML -- The dashboard page or the index page
    '''
    if session.get("logged_in"):
        return render_template("dashboard.html")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    '''
    Renders the login page if the user is not logged in or redirects to the dashboard page

    Returns: HTML -- The login page or the dashboard page
    '''
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == os.environ.get("ADMIN_USERNAME") and password == os.environ.get("ADMIN_PASSWORD"):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))

        flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    '''
    Logs the user out and redirects to the login page

    Returns: HTML -- The index page
    '''
    if request.method == "GET":
        if session.get("logged_in"):
            token = secrets.token_hex(16)
            session["logout_token"] = token
            render_template("logout.html", token=token)
        return redirect(url_for("index"))
    else:
        if session.get("logout_token") == request.form.get("token"):
            session.clear()
            return redirect(url_for("index"))
        else:
            flash("Unauthorized logout request", "error")
            return redirect(url_for("index"))


@app.route("/oragnization/signup", methods=["GET", "POST"])
def signup():
    '''
    Renders the signup page if the user is not logged in or redirects to the dashboard page

    Returns: HTML -- The signup page or the dashboard page
    '''
    if session.get("logged_in") and session.get("user_type") == "organization":
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if not verify_recaptcha(request.form.get("g-recaptcha-response")):
            flash("Invalid reCAPTCHA", "error")
            return render_template("organization_signup.html")

        organization_name = str(request.form.get("organization_name").title())
        organization_domain = str(request.form.get(
            "organization_domain").lower()).replace(" ", "")
        organization_contact_number = str(request.form.get(
            "organization_contact_number").lower()).replace(" ", "")
        organization_contact_email = str(request.form.get(
            "organization_contact_email").lower()).replace(" ", "")

        if DB["organizations"].find_one({"organization_domain": organization_domain}):
            flash("Organization already exists", "error")
            return render_template("organization_signup.html")

        verification_code = secrets.token_hex(32)

        send_email(email="admin@"+organization_domain, name=organization_name,
                   type="organization_verification", verification_code=verification_code)

        DB["organizations"].insert_one({
            "organization_name": organization_name,
            "organization_domain": organization_domain,
            "organization_contact_number": organization_contact_number,
            "organization_contact_email": organization_contact_email,
            "organization_verified": False,
            "verification_code": verification_code,
            "organization_joining_timestamp": time.time(),
        })

        flash("Organization created successfully", "success")
        return redirect(url_for("login"))

    return render_template("organization_signup.html")


@app.route("/test", methods=["GET"])
def test():
    if (send_email(email="projectrexaofficial@gmail.com", name="ProjectRexa",
                   type="organization_verification", verification_code="test")):
        return "Email sent successfully"
    else:
        return "Failed to send email"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=7777)
