# Package imports
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework import status
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.exceptions import NotAuthenticated
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from datetime import datetime
from django.utils.crypto import constant_time_compare
from django.utils.http import base36_to_int
import secrets
from django.core.mail import send_mail
import filetype
from drf_extra_fields.fields import Base64FileField
from rest_framework import serializers


def get_response_schema(schema, message, status_code):
    
    return Response({
        'message': message,
        'status': status_code,
        'results': schema,
    }, status=status_code)


def custom_token_exception_handler(exc, context):

    response = exception_handler(exc, context)

    if (isinstance(exc, InvalidToken)) or (isinstance(exc, NotAuthenticated)):

        return get_response_schema( {}, get_global_error_messages('INVALID_TOKEN'), status.HTTP_401_UNAUTHORIZED)

    return response


def get_tokens_for_user(user):

    refresh = RefreshToken.for_user(user)

    return str(refresh), str(refresh.access_token)


def get_global_success_messages(key):

    data = {

        'RECORD_RETRIEVED': 'The record was successfully retrieved.',
        'RECORD_CREATED': 'The record was successfully created.',
        'RECORD_UPDATED': 'The record was successfully updated.',
        'RECORD_DELETED': 'The record was successfully deleted.',
        'LOGGED_OUT': "User logged out.",
        'LOGGED_IN': 'Logged in successfully.',
        'VERIFIED_SUCCESSFULLY': 'User verified successfully.',
        'PASSWORD_UPDATED': 'Password updated successfully.',
        'STRIPE_SESSION_CREATE': 'Stripe session create.',
        'STRIPE_SESSION_COMPLETED': 'Stripe session create.',
        'WAITING_FOR_APPROVAL': 'Changes are done. Waiting for approval.',
        'RECORD_REJECTED': 'Change request is rejected.',
        'JOB_ALREADY_SAVED': 'This job is already saved.',
        'JOB_SAVED': 'This job successfully saved.',
        'JOB_UNSAVED': 'This job successfully un-saved.',
        'BUSINESS_PROFILE_ALREADY_SAVED': 'This business profile is already saved.',
        'BUSINESS_PROFILE_SAVED': 'This business profile successfully saved.',
        'BUSINESS_PROFILE_UNSAVED': 'This business profile successfully un-saved.',
        'PASS_RESET_LINK_SENT': 'Password reset link sent to your email. Please check.'
    }   
    return data.get(key)


def get_global_error_messages(key):

    data = {
        
        'BAD_REQUEST': 'Bad request.',
        'PERMISSION_DENIED': 'You do not have permission to access this feature.',
        'NOT_FOUND': 'User not found.',
        'DATA_NOT_FOUND': 'Data not found.',
        'INVALID_TOKEN': 'Token is invalid or expired. Please try again.',
        'INVALID_REFRESH_TOKEN': 'Refresh token is invalid or expired. Please try again.',
        'USER_NOT_ACTIVE': 'User is not active.',
        'UNAUTHORIZED': 'Invalid credentials.',
        'UNVERIFIED_ACCOUNT': 'Account is un-verified.',
        'INVALID_LINK': 'Invalid verification link.',
        'FAIL_VERIFICATION_MAIL': 'Failed to send email. Please try again later.',
        'PASSWORD_REQUIRED': 'Password can not be empty',
        'ACCEPT_T_AND_C' : 'Please accept terms and conditions.',
        'EMPTY_PASSWORD' : 'Password can not be empty.',
        'PASSWORD_MISMATCH' : 'Please enter same password and confirm password.',
        'STRIPE_SESSION_ERROR' : 'Error while create stripe session.',
        'STRIPE_INVALID_PARAMETERS' : 'Error in webhook.',
        'STRIPE_WEBHOOK_SIGNATURE_ERROR' : 'Error in webhook signature.',
        'ALREADY_PAID' : 'You have already paid for this job featured.',
        'STRIPE_PAYMENT_SAVE_ERROR' : 'Error while saving payment details.',
        'SOMETHING_WENT_WRONG' : 'Something went wrong. Please try again.',
        'SELECT_ROLE' : 'Please select role for sub-admin.',
        'ROLE_APPROVAL_CONFLICT': 'You cannot assign a role with both "with approval" and "without approval" privileges for the same functionality.',
        'COMPANY_DETAILS_MISSING': 'Company details can not be empty.',

    }
    return data.get(key)


def get_global_values(key):

    data = {

        'CONNECT_INFO_WITH_APPROVAL': 1,
        'CONNECT_INFO_WITHOUT_APPROVAL': 2,
        'COMPANY_MISSION_WITH_APPROVAL': 3,
        'COMPANY_MISSION_WITHOUT_APPROVAL': 4,
        'POSITIVE_CHANGES_WITH_APPROVAL': 5,
        'POSITIVE_CHANGES_WITHOUT_APPROVAL': 6,
        'OPENING_HOURS_WITH_APPROVAL': 7,
        'OPENING_HOURS_WITHOUT_APPROVAL': 8,
        'LOGO_CHANGE_WITH_APPROVAL': 9,
        'LOGO_CHANGE_WITHOUT_APPROVAL': 10,
        'STORY_CAROUSEL_WITH_APPROVAL': 11,
        'STORY_CAROUSEL_WITHOUT_APPROVAL': 12,
        'JOB_WITH_APPROVAL': 13,
        'JOB_WITHOUT_APPROVAL': 14,
        'PRODUCT_SERVICES_WITH_APPROVAL': 15,
        'PRODUCT_SERVICES_WITHOUT_APPROVAL': 16,
        
    }   

    return data.get(key)


def get_serializer_error_msg(error): 

    return {settings.REST_FRAMEWORK["NON_FIELD_ERRORS_KEY"]: error}


class CustomTokenGenerator(PasswordResetTokenGenerator):

    def make_token(self, user, expiration=None):

        if expiration is None:
            expiration = self._num_seconds(self._now()) + settings.PASSWORD_RESET_TIMEOUT
        else:
            expiration = self._num_seconds(expiration)
        return self._make_token_with_timestamp(
            user,
            expiration,
            self.secret,
        )

    def check_token(self, user, token):

        if not (user and token):
            return False
        
        try:
            ts_b36, _ = token.split("-")

        except ValueError:
            return False

        try:

            ts = base36_to_int(ts_b36)

        except ValueError:
            return False

        for secret in [self.secret, *self.secret_fallbacks]:

            if constant_time_compare(
                self._make_token_with_timestamp(user, ts, secret),
                token,
            ):
                break
        else:
            return False

        if (self._num_seconds(self._now()) - ts) > settings.PASSWORD_RESET_TIMEOUT:

            return False

        return True

    def _make_hash_value(self, user, timestamp):

        login_timestamp = (
            ""
            if user.last_login is None
            else user.last_login.replace(microsecond=0, tzinfo=None)
        )
        email_field = user.get_email_field_name()

        email = getattr(user, email_field, "") or ""

        return f"{user.pk}{user.password}{login_timestamp}{timestamp}{email}"

    def _num_seconds(self, dt):

        return int((dt - datetime(2001, 1, 1)).total_seconds())

    def _now(self):

        return datetime.now()


custom_token_generator = CustomTokenGenerator()


def send_email_with_link(request, user, subject, email_message, url_name):
    current_site = get_current_site(request)
    domain = current_site.domain

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = custom_token_generator.make_token(user)
    
    verification_url = reverse(url_name)
    verification_link = f"http://{domain}{verification_url}?uidb64={uid}&token={token}"
    
    email_message = email_message.format(user=user.email, verification_link=verification_link)
    
    email = EmailMultiAlternatives(
        subject,
        strip_tags(email_message),
        settings.EMAIL_HOST_USER,
        [user.email],
    )

    email.attach_alternative(email_message, "text/html")

    email.send()
    
    return "Email sent successfully"


def send_verification_email(request, user):

    subject = "Verify Your Email"

    email_message = (
        "<p>Hi {user},</p>"
        "<p>Please verify your account by visiting the following link:</p>"
        "<p><a href='{verification_link}'>{verification_link}</a></p>"
        "<p>Thank you!</p>"
    )

    return send_email_with_link(request, user, subject, email_message, 'verify-email-to-verify-user')


def send_forgot_password_email_business_user(request, user):

    subject = "Reset Your Password"

    email_message = (
        "<p>Hi {user},</p>"
        "<p>Click bellow link to redirect on forgot password page.</p>"
        "<p><a href='{verification_link}'>{verification_link}</a></p>"
        "<p>Thank you!</p>"
    )
    
    return send_email_with_link(request, user, subject, email_message, 'forgot-password-page')


def generate_auth_token():
    return secrets.token_urlsafe(32)


def send_auth_token_email(user, token, base_url):

    try:

        subject = 'Login Authentication Link'
        message = f'Click the following link to log in: {base_url}/user/authenticate/{token}/'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

        return True 
    except Exception as e:
        return False


def sub_admin_account_create_email(user, base_url, user_password):
    try:
        subject = 'Account has been created on OneHeartMarket!!!'
        message = (
            "Hello,\n"
            "We have created your account on One Heart Market.\n"
            f"Click the following link to log in: {base_url}\n"
            f"Your login credentials:\n"
            f"Email: {user.email}\n"
            f"Password: {user_password}\n"
            "Thank you!"
        )
        # Assuming strip_tags is imported from somewhere else
        message = strip_tags(message)

        from_email = settings.EMAIL_HOST_USER
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

        return True
    except Exception as e:
        return False
    

def wrong_login_attempt(user):

    subject = 'Wrong login attempt'
    message = f'Wrong login attempt'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list)


def get_list_difference(list1, list2):
    return list(set(list1) - set(list2))


def check_role_id_blockers(role_id_list):

    for role in role_id_list:
        conflicting_role = role + 1 if role % 2 == 1 else role - 1
        if conflicting_role in role_id_list:
            return False
        
    return True


class CustomBase64File(Base64FileField):
    """ Utility: Class: CustomBase64File class for validating the uploaded file's extension """

    ALLOWED_TYPES = ['pdf']

    def get_file_extension(self, filename, decoded_file):
        """ Method: Override the get_file_extension method for actual Validation Logic """

        try:
            kind = filetype.guess(decoded_file)
            if kind.extension in self.ALLOWED_TYPES:
                return kind.extension 
            self.INVALID_TYPE_MESSAGE = "Files with the '" + str(kind.extension) + "' extension are not allowed."
        except Exception as e:
            raise serializers.ValidationError(e)
