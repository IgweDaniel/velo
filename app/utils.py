from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.core.mail import send_mail


# def send_email(subject, template_name, context, recipient_list):
#     message = render_to_string(template_name, context)
#     email_from = settings.EMAIL_HOST_USER
#     email = EmailMultiAlternatives(subject, message, email_from, recipient_list)
#     email.attach_alternative(message, "text/html")
#     email.send()


def send_otp_email(email, otp):
    subject = "Your OTP Code"
    message = render_to_string("otp_email.html", {"email": email, "otp": otp})
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list, html_message=message)
