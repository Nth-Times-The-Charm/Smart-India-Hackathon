"""
This file contains the main code for the CertSecure backend service
"""
import hashlib
import secrets
import os
import time
from flask import Flask, render_template, request, redirect, url_for, flash, session
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
import pyotp


# Global Variables
dotenv.load_dotenv()

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

    mongo_client = pymongo.MongoClient(
        f"mongodb+srv://{os.environ.get('MONGODB_USERNAME')}:{os.environ.get('MONGODB_PASSWORD')}@shi-cluster.rqdq2aa.mongodb.net/?retryWrites=true&w=majority")
    mongo_db = mongo_client["certsecure"]

    try:
        mongo_client.server_info()
        print(Fore.GREEN + "Connected to MongoDB Atlas")
        return mongo_db

    except Exception as danger:
        if number_of_tries < 3:
            time.sleep(5*number_of_tries)
            connect_mongodb(number_of_tries + 1)
        raise Exception(
            Fore.RED + "Failed to connect to MongoDB Atlas") from danger


def connect_redis(number_of_tries=0):
    '''
    Connects to Redis

    Keyword Arguments: number_of_tries {Integer} -- The number of times 
    the function has been called (default: {0})

    Raises: Exception -- If the function fails to connect to Redis

    Returns: None
    '''
    redis_client = redis.from_url(
        f"rediss://{os.environ.get('REDIS_USERNAME')}:{os.environ.get('REDIS_PASSWORD')}@shi-redis-projectrexa.aivencloud.com:25156")

    try:
        redis_client.ping()
        print(Fore.GREEN + "Connected to Redis")
        return redis_client

    except Exception as danger:
        if number_of_tries < 3:
            time.sleep(5*number_of_tries)
            connect_redis(number_of_tries + 1)
        raise Exception(Fore.RED + "Failed to connect to Redis") from danger


DB = connect_mongodb()
REDIS_CLIENT = connect_redis()

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
        raise Exception(Fore.RED + "Failed to hash the file") from danger


def send_email(email, name, mail_type, verification_code=None):
    '''
    Sends an email to the user

    Arguments: email {String} -- The email of the user
               mail_type {String} -- The type of email to be sent

    Keyword Arguments: verification_code {String} -- The verification code to be sent (default: {None})

    Raises: Exception -- If the function fails to send the email

    Returns: None
    '''
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration))

    # Case statement switched to if-else statements due to no support for 3.10 on Vercel
    if mail_type == "organization-verification":
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
    except ApiException:
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
                                     "secret": os.environ.get("RECAPTCHA_SECRET_KEY"), "response": response}, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=5).json()
        return api_response.get("success")
    except:
        return False


def hash_password(password):
    '''
    Hashes the password using bcrypt
    '''
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(password, hashed_password):
    '''
    Checks if the password matches the hashed password
    '''
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


def check_2fa(organization_2fa_secret, organization_2fa):
    '''
    Checks if the 2FA code is valid
    '''
    return pyotp.TOTP(organization_2fa_secret).verify(organization_2fa)

# Routes


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
        if session.get("user_type") == "organization":
            return (f"Organization ID: {session.get('organization_id')}<br>Organization Name: {session.get('organization_name')}<br>Organization Domain: {session.get('organization_domain')}<br>Organization Contact Email: {session.get('organization_contact_email')}")
        elif session.get("user_type") == "user":
            return (f"User ID: {session.get('user_id')}<br>User Name: {session.get('user_name')}<br>User Email: {session.get('user_email')}")
        else:
            return redirect(url_for("logout"))
    return redirect(url_for("login"))


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
        if session.get("logged_in") and request.form.get("logout_token") == session.get("logout_token"):
            session.clear()
            flash("Logged out successfully", "success")
            return redirect(url_for("index"))
        return redirect(url_for("index"))


@app.route("/organization/login", methods=["GET", "POST"])
def organization_login():
    '''
    Renders the login page if the user is not logged in or redirects to the dashboard page

    Returns: HTML -- The login page or the dashboard page
    '''
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        turnstile_response = request.form.get("cf-turnstile-response")

        if not turnstile_response:
            flash("Invalid CAPTCHA response, please try again", "danger")
            return render_template("organization_login.html")

        if not verify_recaptcha(turnstile_response):
            flash("Invalid CAPTCHA response, please try again", "danger")
            return render_template("organization_login.html")

        if not request.form.get("organization_domain") or not request.form.get("organization_password") or not request.form.get("organization_2fa"):
            flash("Please fill all the fields", "danger")
            return render_template("organization_login.html")

        organization_domain = str(request.form.get(
            "organization_domain").lower()).replace(" ", "").replace("https://", "").replace("http://", "").replace("/", "").replace("www.", "")
        organization_password = str(request.form.get(
            "organization_password").lower()).replace(" ", "")

        if "." not in organization_domain:
            flash("Invalid domain, please try again", "danger")
            return render_template("organization_login.html")

        if not DB["organizations"].find_one({"organization_domain": organization_domain}):
            flash("Organization not found, please try again", "danger")
            return render_template("organization_login.html")

        if not check_password(organization_password, DB["organizations"].find_one({"organization_domain": organization_domain})["organization_password"]):
            flash("Invalid domain or password, please try again", "danger")
            return render_template("organization_login.html")

        if not check_2fa(DB["organizations"].find_one({"organization_domain": organization_domain})["two_factor_secret"], request.form.get("organization_2fa")):
            flash("Invalid 2FA code, please try again", "danger")
            return render_template("organization_login.html")

        if not DB["organizations"].find_one({"organization_domain": organization_domain})["organization_verified"]:
            session["organization_id"] = DB["organizations"].find_one(
                {"organization_domain": organization_domain})["organization_id"]
            flash("Organization not verified, &nbsp; <a href='/organization/verify-domain'>click here to verify</a>", "danger")
            return render_template("organization_login.html")

        organization_information = DB["organizations"].find_one(
            {"organization_domain": organization_domain})

        session["logged_in"] = True
        session["user_type"] = "organization"
        session["organization_id"] = organization_information["organization_id"]
        session["organization_name"] = organization_information["organization_name"]
        session["organization_domain"] = organization_information["organization_domain"]
        session["organization_contact_email"] = organization_information["organization_contact_email"]

        return redirect(url_for("dashboard"))

    return render_template("organization_login.html")


@app.route("/organization/signup", methods=["GET", "POST"])
def organization_signup():
    '''
    Renders the signup page if the user is not logged in or redirects to the dashboard page

    Returns: HTML -- The signup page or the dashboard page
    '''
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if session.get("organization_id"):
        return redirect(url_for("organization_2fa"))

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
            "organization_domain").lower()).replace(" ", "").replace("https://", "").replace("http://", "").replace("/", "").replace("www.", "")
        organization_contact_email = str(request.form.get(
            "organization_contact_email").lower()).replace(" ", "")
        organization_password = str(request.form.get(
            "organization_password").lower()).replace(" ", "")
        agree_to_terms = request.form.get("agree_to_terms")

        if "." not in organization_domain:
            flash("Invalid domain, please try again", "danger")
            return render_template("organization_signup.html")

        if "@" not in organization_contact_email or "." not in organization_contact_email:
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

        while DB["organizations"].find_one({"organization_id": organization_id}) is not None:
            organization_id = secrets.token_hex(8)

        DB["organizations"].insert_one({
            "organization_id": organization_id,
            "organization_name": organization_name,
            "organization_domain": organization_domain,
            "organization_contact_email": organization_contact_email,
            "organization_password": hash_password(organization_password),
            "organization_verified": False,
            "verification_code": verification_txt_record,
            "organization_2fa": False,
            "organization_joining_timestamp": time.time(),
        })
        session["organization_id"] = organization_id
        return redirect(url_for("organization_2fa"))

    return render_template("organization_signup.html")


@app.route("/organization/2fa_setup", methods=["GET", "POST"])
def organization_2fa():
    '''
    Renders the 2FA page if the user is not logged in and has not set up 2FA or redirects to the dashboard page

    Returns: HTML -- The 2FA page or the dashboard page
    '''

    if request.method == "POST":
        if session.get("logged_in"):
            return redirect(url_for("login"))

        if not session.get("organization_id"):
            return redirect(url_for("organization_signup"))

        if not session.get("two_factor_secret") or not session.get("two_factor_recovery_code"):
            return redirect(url_for("organization_signup"))

        if not request.form.get("cf-turnstile-response"):
            flash("Invalid CAPTCHA response, please try again", "danger")
            return render_template("organization_2fa.html", two_factor_uri=session.get("two_factor_uri"), two_factor_recovery_code=session.get("two_factor_recovery_code"))

        if not verify_recaptcha(request.form.get("cf-turnstile-response")):
            flash("Invalid CAPTCHA response, please try again", "danger")
            return render_template("organization_2fa.html", two_factor_uri=session.get("two_factor_uri"), two_factor_recovery_code=session.get("two_factor_recovery_code"))

        if not DB["organizations"].find_one({"organization_id": session.get("organization_id")}):
            session.clear()
            return redirect(url_for("organization_signup"))

        if DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_2fa"]:
            return redirect(url_for("verify_domain"))

        if not request.form.get("2fa_code"):
            flash("Please fill all the fields", "danger")
            return render_template("organization_2fa.html", two_factor_uri=session.get("two_factor_uri"), two_factor_recovery_code=session.get("two_factor_recovery_code"))

        print(request.form.get("2fa_code"))
        if not check_2fa(session.get("two_factor_secret"), request.form.get("2fa_code")):
            flash("Invalid 2FA code, please try again", "danger")
            return render_template("organization_2fa.html", two_factor_uri=session.get("two_factor_uri"), two_factor_recovery_code=session.get("two_factor_recovery_code"))

        DB["organizations"].update_one({"organization_id": session.get("organization_id")}, {
            "$set": {"two_factor_secret": session.get("two_factor_secret"), "two_factor_recovery_code": session.get("two_factor_recovery_code")}})

        DB["organizations"].update_one({"organization_id": session.get("organization_id")}, {
            "$set": {"organization_2fa": True}})

        session.pop("two_factor_secret")
        session.pop("two_factor_recovery_code")

        flash("2FA enabled successfully", "success")

        return redirect(url_for("verify_domain"))

    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if not session.get("organization_id"):
        return redirect(url_for("organization_signup"))

    if DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_2fa"]:
        return redirect(url_for("verify_domain"))

    two_factor_secret = pyotp.random_base32()

    two_factor_recovery_code = secrets.token_hex(32)

    two_factor_uri = pyotp.totp.TOTP(two_factor_secret).provisioning_uri(
        name=DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_name"], issuer_name="CertSecure")

    session["two_factor_secret"] = two_factor_secret
    session["two_factor_recovery_code"] = two_factor_recovery_code
    session["two_factor_uri"] = two_factor_uri

    return render_template("organization_2fa.html", two_factor_uri=two_factor_uri, two_factor_recovery_code=two_factor_recovery_code)


@app.route("/organization/verify-domain", methods=["GET", "POST"])
def verify_domain():
    '''
    Renders the verify domain page if the user is not logged in or redirects to the dashboard page

    Returns: HTML -- The verify domain page or the dashboard page

    '''
    if request.method == "GET":
        if not session.get("logged_in") and session.get("organization_id"):
            if not DB["organizations"].find_one({"organization_id": session.get("organization_id")}):
                session.clear()
                flash("Organization not found, signup to continue", "danger")
                return redirect(url_for("organization_signup"))

            if not DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_2fa"]:
                flash("2FA not enabled, please enable 2FA to continue", "danger")
                return redirect(url_for("organization_2fa"))

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
                session.clear()
                flash("Organization not found, signup to continue", "danger")
                return redirect(url_for("organization_signup"))

            if not DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_2fa"]:
                flash("2FA not enabled, please enable 2FA to continue", "danger")
                return redirect(url_for("organization_2fa"))

            if DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_verified"]:
                flash("Domain already verified", "danger")
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
                flash("TXT record does not match", "danger")
                return render_template("verify_domain.html", verification_text_record=verification_text_record, domain_name=DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_domain"], domain_txt_record=domain_txt_record)
            except:
                flash("No TXT record found", "danger")
                return render_template("verify_domain.html", verification_text_record=verification_text_record, domain_name=DB["organizations"].find_one({"organization_id": session.get("organization_id")})["organization_domain"])
        return redirect(url_for("organization_signup"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
