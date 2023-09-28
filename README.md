# Smart-India-Hackathon
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
