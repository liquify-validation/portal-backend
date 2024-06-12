import requests
import os
from config import config

mailgunAPIKey = config.Config.MAILGUN_API
EMAIL_FROM = config.Config.EMAIL_FROM

def send_password_reset_email(email, reset_link):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, 'Resources/forgot_password.html')

    with open(template_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    html_content = html_content.replace('{{password_reset_link}}', reset_link)

    email_data = {
        "from": EMAIL_FROM,
        "to": email,
        "subject": "Password Reset Request",
        "html": html_content,
    }

    response = requests.post(
        "https://api.mailgun.net/v3/mailerus.liquify.io/messages",
        auth=("api", mailgunAPIKey),
        data=email_data
    )

    return response


def send_verification_email(email, verification_link):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, 'Resources/verification.html')

    with open(template_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    html_content = html_content.replace('{{verification_link}}', verification_link)

    email_data = {
        "from": EMAIL_FROM,
        "to": email,
        "subject": "Verify your email address",
        "html": html_content
    }

    response = requests.post(
        "https://api.mailgun.net/v3/mailerus.liquify.io/messages",
        auth=("api", mailgunAPIKey),
        data=email_data
    )

    return response

def invite_user(email, org, inviter, verification_link):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, 'Resources/org_invite.html')

    with open(template_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    html_content = html_content.replace('{{verification_link}}', verification_link)
    html_content = html_content.replace('{{inviter}}', inviter)
    html_content = html_content.replace('{{org}}', org)


    email_data = {
        "from": EMAIL_FROM,
        "to": email,
        "subject": "You have been invited",
        "html": html_content
    }

    response = requests.post(
        "https://api.mailgun.net/v3/mailerus.liquify.io/messages",
        auth=("api", mailgunAPIKey),
        data=email_data
    )

    return response

def send_deleted_user_email(email, org_name, signup_link):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, 'Resources/deleted_user.html')

    with open(template_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    html_content = html_content.replace('{{ org_name }}', org_name)
    html_content = html_content.replace('{{ signup_link }}', signup_link)

    email_data = {
        "from": EMAIL_FROM,
        "to": email,
        "subject": "Account Deletion Notification",
        "html": html_content,
    }

    response = requests.post(
        "https://api.mailgun.net/v3/mailerus.liquify.io/messages",
        auth=("api", mailgunAPIKey),
        data=email_data
    )

    return response