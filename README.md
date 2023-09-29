# Smart-India-Hackathon

# CertSecure - Secure Certification Management System

CertSecure is a web application built using Flask, MongoDB, Redis, SendinBlue, and other technologies. It serves as a secure certification management system that allows organizations to manage their certifications and domains securely. This README will guide you through setting up and running the application.

## Features

- User registration and login.
- Organization signup and domain verification.
- Secure password hashing.
- Integration with reCAPTCHA for form validation.
- Email verification and notifications using SendinBlue.
- Session management using Redis.
- Dashboard for authenticated users.
- TXT record-based domain verification.

## Prerequisites

Before running the application, ensure you have the following prerequisites installed:

- Python (3.x recommended)
- Flask
- pymongo (Python MongoDB driver)
- redis-py (Python Redis client)
- sib-api-v3-sdk (SendinBlue Python client)
- colorama (for colored console output)
- Flask-Session (for managing sessions)
- requests (for making HTTP requests)
- bcrypt (for secure password hashing)

You can install these dependencies using pip:

```bash
pip install Flask pymongo redis sib-api-v3-sdk colorama Flask-Session requests bcrypt
```

Additionally, you need to set up the following environment variables in a `.env` file:

- `MONGODB_USERNAME`: Your MongoDB Atlas username.
- `MONGODB_PASSWORD`: Your MongoDB Atlas password.
- `REDIS_USERNAME`: Your Redis username.
- `REDIS_PASSWORD`: Your Redis password.
- `SECRET_KEY`: A secure random string for Flask session management.
- `SENDINBLUE_API_KEY`: Your SendinBlue API key.
- `ADMIN_USERNAME`: The admin username for logging in.
- `ADMIN_PASSWORD`: The admin password for logging in.
- `RECAPTCHA_SECRET_KEY`: Your reCAPTCHA secret key.

## Database Configuration

CertSecure uses MongoDB to store organization data. Make sure you have a MongoDB Atlas cluster set up and provide the cluster connection URI in the `connect_mongodb` function.

## Running the Application

To run the application, use the following command:

```bash
python app.py
```

The application will start, and you can access it in your web browser at `http://localhost:7777`.

## Usage

### Admin Login

1. Access the login page by going to `http://localhost:7777/login`.
2. Enter the admin username and password provided in your environment variables.
3. Click the "Login" button.
4. Upon successful login, you will be redirected to the dashboard.

### Organization Signup

1. Access the organization signup page by going to `http://localhost:7777/organization/signup`.
2. Fill in the organization details, including name, domain, contact email, and password.
3. Complete the reCAPTCHA challenge to prove you are not a robot.
4. Agree to the terms and conditions.
5. Click the "Signup" button.
6. You will be redirected to the domain verification page.

### Domain Verification

1. Access the domain verification page by going to `http://localhost:7777/organization/verify-domain`.
2. Verify your domain by setting the TXT record in your DNS configuration. The application will check if the TXT record matches the one generated during signup.
3. If the verification is successful, you will receive a success message.

### Dashboard

- Authenticated users, including the admin and verified organizations, will see a dashboard.

## Customization

You can customize this application further by adding more features, improving the UI, or integrating additional functionality as needed. The provided code serves as a foundation for building a secure certification management system.

Feel free to modify and extend this code to suit your specific requirements.

Enjoy using CertSecure, your Secure Certification Management System!

# Domain Verification HTML Page Readme

This HTML code represents a web page for domain verification using a TXT record. It provides instructions to users on how to verify their domain ownership by adding a specific TXT record to their DNS settings.

## Table of Contents
- [Description](#description)
- [Page Structure](#page-structure)
- [Instructions](#instructions)
- [Flashed Messages](#flashed-messages)
- [Verification Form](#verification-form)
- [TXT Record Value Display](#txt-record-value-display)

## Description
This HTML page is designed to guide users through the process of verifying domain ownership using a TXT record. It provides clear instructions and a form for initiating the verification process.

## Page Structure
- **DOCTYPE Declaration**: Specifies that this is an HTML5 document.
- **Head Section**: Contains meta information, title, icon, CSS stylesheets, and a JavaScript script.
- **Body Section**: The main content of the page is within the `<body>` tags.
  - **Alert Messages**: Flash messages are displayed at the top of the page to provide important information. Users can close these messages by clicking the "×" button.
  - **Main Content**: Contains the core instructions and elements for domain verification.
    - **Page Title**: Displays "Domain verification using TXT record" as the main title.
    - **Domain Name**: Displays the domain name being verified.
    - **Instructions**: Provides a set of step-by-step instructions for users to follow.
    - **Verification Code**: Displays the TXT record details that users need to add to their DNS settings.
    - **Verification Button**: A form with a verification button that initiates the verification process.
    - **Current TXT Record Value**: Displays the current value of the TXT record associated with the domain.

## Instructions
The HTML page provides clear instructions to guide users through the domain verification process:

1. **Login to your DNS provider**: Users are instructed to log in to their DNS provider (e.g., GoDaddy, Cloudflare, Namecheap) and navigate to the DNS settings for their domain.
2. **Add a new TXT record**: Users are guided on adding a new TXT record with specific details, including the name and value.
3. **Verification Button**: Once the TXT record is added, users can click the "Verify Domain" button to initiate the verification process.
4. **DNS Propagation Time**: Users are informed that DNS changes may take up to 24 hours to take effect. If they still see the same page after 24 hours, they are provided with a contact email address for support.

## Flashed Messages
- Flash messages are used to display important information to users. These messages have categories (e.g., success, error) and can be closed by clicking the "×" button.

## Verification Form
- The verification form includes a reCAPTCHA widget (`cf-turnstile`) for added security. Users need to complete the CAPTCHA and click the "Verify Domain" button to proceed with verification.

## TXT Record Value Display
- The page displays the current value of the TXT record associated with the domain. If no TXT record is found, it defaults to "No TXT record found."
