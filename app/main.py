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
import dns.resolver
import requests
import bcrypt


# Global Variables
dotenv.load_dotenv()
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

    except Exception as danger:
        if number_of_tries < 3:
            time.sleep(5*number_of_tries)
            connect_mongodb(number_of_tries + 1)
        raise Exception(
            Fore.RED + "Failed to connect to MongoDB Atlas") from danger


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

    except Exception as danger:
        if number_of_tries < 3:
            time.sleep(5*number_of_tries)
            connect_redis(number_of_tries + 1)
        raise Exception(Fore.RED + "Failed to connect to Redis") from danger


connect_mongodb()
connect_redis()

# Flask Config


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
    except Exception as danger:
        raise Exception(Fore.RED + f"Failed to hash file: {danger}")


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

    # Case statement switched to if-else statements due to no support for 3.10 on Vercel
    if type == "organization-verification":
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

    else:
        return False
    try:
        api_instance.send_transac_email(send_smtp_email)
        return True
    except ApiException as e:

        return False


def verify_recaptcha(response):
    '''
    Verifies the reCAPTCHA response

    Arguments: response {String} -- The reCAPTCHA response

    Raises: Exception -- If the function fails to verify the reCAPTCHA response

    Returns: Boolean -- True if the reCAPTCHA response is valid else False
    '''
    try:
        api_response = requests.post("https://challenges.cloudflare.com/turnstile/v0/siteverify", data={
                                     "secret": os.environ.get("RECAPTCHA_SECRET_KEY"), "token": response}).json()
        if api_response.get("success"):
            return True
        else:
            return False
    except ApiException as e:
        return False
# Flask Routes


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


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

        flash("Invalid username or password", "danger")

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
            flash("Unauthorized logout request", "danger")
            return redirect(url_for("index"))


@app.route("/organization/signup", methods=["GET", "POST"])
def organization_signup():
    '''
    Renders the signup page if the user is not logged in or redirects to the dashboard page

    Returns: HTML -- The signup page or the dashboard page
    '''
    if session.get("logged_in") and session.get("user_type") == "organization":
        return redirect(url_for("dashboard"))

    if session.get("organization_id"):
        return redirect(url_for("verify_domain"))

    print(session.get("organization_id"))

    if request.method == "POST":
        turnstile_response = request.form.get("cf-turnstile-response")

        if not turnstile_response:
            flash("Invalid CAPTCHA response, please try again", "danger")
            return render_template("organization_signup.html")

        if not verify_recaptcha(turnstile_response):
            flash("Invalid CAPTCHA response, please try again", "danger")
            return render_template("organization_signup.html")

        if not request.form.get("organization_name") or not request.form.get("organization_domain") or not request.form.get("organization_contact_email") or not request.form.get("organization_password"):
            flash("Please fill all the fields", "danger")
            return render_template("organization_signup.html")

        organization_name = str(request.form.get("organization_name").title())
        organization_domain = str(request.form.get(
            "organization_domain").lower()).replace(" ", "")
        organization_contact_email = str(request.form.get(
            "organization_contact_email").lower()).replace(" ", "")
        organization_password = str(request.form.get(
            "organization_password").lower()).replace(" ", "")
        agree_to_terms = request.form.get("agree_to_terms")

        if not "." in organization_domain:
            flash("Invalid domain, please try again", "danger")
            return render_template("organization_signup.html")

        if not "@" in organization_contact_email or not "." in organization_contact_email:
            flash("Invalid email address, please try again", "danger")
            return render_template("organization_signup.html")

        if agree_to_terms != "on":
            flash("Please agree to the terms and conditions", "danger")
            return render_template("organization_signup.html")

        if DB["organizations"].find_one({"organization_domain": organization_domain}):
            flash("Organization already exists", "danger")
            return render_template("organization_signup.html")

        verification_txt_record = "certsecure-verification-" + \
            secrets.token_hex(32)
        organization_id = secrets.token_hex(8)

        while DB["organizations"].find_one({"organization_id": organization_id}) != None:
            organization_id = secrets.token_hex(8)

        DB["organizations"].insert_one({
            "organization_id": organization_id,
            "organization_name": organization_name,
            "organization_domain": organization_domain,
            "organization_contact_email": organization_contact_email,
            "organization_password": hash_password(organization_password),
            "organization_verified": False,
            "verification_code": verification_txt_record,
            "organization_joining_timestamp": time.time(),
        })
        session["organization_id"] = organization_id
        return redirect(url_for("verify_domain"))

    return render_template("organization_signup.html")
            
# Tarun, Bharat, Laxman code from here👇            
@app.route('/organization/login', methods=['GET', 'POST'])
def organization_login():
    if organization_logged_in:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        organization_domain = request.form.get('organization_domain')
        organization_password = request.form.get('organization_password')

        if check_organization_credentials(organization_domain, organization_password):
            session['organization_domain'] = organization_domain
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials, please try again', 'danger')

    return render_template('organization_login.html')

def check_organization_credentials(domain, password):
# bhar lio mujhe ni aata 😁
# Return True if valid, False otherwise ok bro 👍 GN

    

@app.route("/organization/verify-domain", methods=["GET", "POST"])
def verify_domain():
    if request.method == "GET":
        if not session.get("logged_in") and session.get("organization_id"):
            if not DB["organizations"].find_one({"organization_id": session.get("organization_id")}):
                flash("Organization not found, signup to continue", "danger")
                return redirect(url_for("organization_signup"))
            if DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_verified"]:
                flash("Domain already verified", "danger")
                return redirect(url_for("dashboard"))
            verification_text_record = DB["organizations"].find_one(
                {"organization_id": session.get("organization_id")})["verification_code"]
            domain_name = DB["organizations"].find_one(
                {"organization_id": session.get("organization_id")})["organization_domain"]
            return render_template("verify_domain.html", verification_text_record=verification_text_record, domain_name=domain_name)
        flash("Organization not found, signup to continue", "danger")
        return redirect(url_for("organization_signup"))
    elif request.method == "POST":
        if not session.get("logged_in") and session.get("organization_id"):
            if not DB["organizations"].find_one({"organization_id": session.get("organization_id")}):
                return redirect(url_for("organization_signup"))
            if DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_verified"]:
                return redirect(url_for("dashboard"))
            verification_text_record = DB["organizations"].find_one(
                {"organization_id": session.get("organization_id")})["verification_code"]
            try:

                domain_txt_record = dns.resolver.resolve("TXT-CERTSECURE-DOMAIN-VERIFICATION."+DB["organizations"].find_one(
                    {"organization_id": session.get("organization_id")})["organization_domain"], "TXT")[0].to_text().lower().replace('"', '').replace(" ", "")

                if domain_txt_record == verification_text_record:
                    DB["organizations"].update_one({"organization_id": session.get("organization_id")}, {
                        "$set": {"organization_verified": True}})
                    flash("Domain verified successfully", "success")
                    return "Domain verified successfully"
                else:
                    flash("TXT record does not match", "danger")
                    return render_template("verify_domain.html", verification_text_record=verification_text_record, domain_name=DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_domain"], domain_txt_record=domain_txt_record)
            except Exception as danger:
                flash("No TXT record found", "danger")
                return render_template("verify_domain.html", verification_text_record=verification_text_record, domain_name=DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_domain"])
        return redirect(url_for("organization_signup"))


if __name__ == "__main__":
    app.run(host="0.0.0.0")
