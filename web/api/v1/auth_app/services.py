import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NamedTuple, Optional, TypeVar
from urllib.parse import quote, urlencode, urljoin

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import signing
from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from api.email_services import BaseEmailHandler
from main.decorators import except_shell

from .user_services import UserQueryService

User  = get_user_model()


class CreateUserData(NamedTuple):
    first_name: str
    last_name: str
    email: str
    password_1: str
    password_2: str


class ConfirmationEmailHandler(BaseEmailHandler):
    FRONTEND_URL = settings.FRONTEND_URL
    FRONTEND_PATH = '/auth/confirm'
    TEMPLATE_NAME = 'emails/verify_email.html'

    def _get_activate_url(self) -> str:
        """Формирует полный URL для подтверждения"""
        query_params = urlencode({
            'key': self.user.confirmation_key,
            'email': self.user.email,
        })

        full_url = f"{self.FRONTEND_URL}/{self.FRONTEND_PATH}?{query_params}"
        return full_url

    def email_kwargs(self, **kwargs) -> dict:
        activate_url = self._get_activate_url()

        return {
            'subject': _('Register confirmation email'),
            'to_email': self.user.email,
            'context': {
                'user': self.user.full_name,
                'activate_url': activate_url,
                'expiry_hours': getattr(settings, 'CONFIRM_EMAIL_EXPIRY_HOURS', 24)
            },
        }


@dataclass
class PasswordResetDTO:
    uid: str
    token: str

    def __post_init__(self):
        """Очистка uid от обертки b''"""
        # Удаляем обертку b'...' если она есть
        if self.uid.startswith("b'") and self.uid.endswith("'"):
            self.uid = self.uid[2:-1]

    def to_dict(self) -> dict:
        """Преобразование в словарь"""
        return {
            'uid': self.uid,
            'token': self.token
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'PasswordResetDTO':
        """Создание DTO из словаря"""
        return cls(
            uid=data.get('uid', ''),
            token=data.get('token', '')
        )


class PasswordResetManager:
    def __init__(self):
        self.token_generator = default_token_generator

    def generate(self, user: User) -> PasswordResetDTO:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = self.token_generator.make_token(user)
        return PasswordResetDTO(uid=uid, token=token)

    def validate(self, uid: str, token: str, raise_exception: bool = True) -> User | None:
        errors = []
        user = self._get_user_by_uid(uid)
        if not user:
            errors.append({'uid': ['Invalid value']})
        if user and not self._validate_token(user, token):
            errors.append({'token': ['Invalid value']})
        if errors and raise_exception:
            raise ValidationError(errors)
        return user

    @staticmethod
    def _get_user_by_uid(uid: str) -> User | None:
        try:
            user_id = urlsafe_base64_decode(uid).decode()
            return User.objects.get(id=user_id)
        except (User.DoesNotExist, ValueError):
            return None

    def _validate_token(self, user: User, token: str) -> bool:
        return self.token_generator.check_token(user, token)


class PasswordResetService:
    def __init__(self, user):
        self.user = user

    def send_email(self, reset_url: str):
        subject = "Password Reset Request"
        message = f"""
        Hello {self.user.first_name or self.user.email},

        You requested a password reset. Click the link below to reset your password:

        {reset_url}

        If you didn't request this, please ignore this email.

        This link will expire in 24 hours.
        """

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[self.user.email],
            fail_silently=False,
        )


class PasswordResetHandler:
    def __init__(self, email: str):
        self.email = email
        self.frontend_url = settings.FRONTEND_URL
        self.frontend_path = 'api/v1/auth/password/reset/confirm'

    def reset_password(self):
        user = UserQueryService().get_user_by_email(self.email)
        if not user:
            return
        reset_url = self._get_reset_url(user)
        PasswordResetService(user).send_email(reset_url=reset_url)

    def _get_reset_url(self, user) -> str:
        values = PasswordResetManager().generate(user)
        url = urljoin(self.frontend_url, f"{self.frontend_path}/{values.token}/")
        reset_url = f'{url}?uid={values.uid}'
        return quote(reset_url, safe=':/?&=')


class AuthAppService:
    @staticmethod
    def is_user_exist(email: str) -> bool:
        return User.objects.filter(email=email).exists()

    @staticmethod
    @except_shell((User.DoesNotExist,))
    def get_user(email: str) -> User:
        return User.objects.get(email=email)

    @transaction.atomic()
    def create_user(self, validated_data: dict):
        data = CreateUserData(**validated_data)
        pattern = re.compile(r'[@.]')
        username = pattern.sub('_', data.email)
        user = User.objects.create_user(
            # username=username,
            email=data.email,
            password=data.password_1,
            first_name=data.first_name,
            last_name=data.last_name,
            is_active=False,
        )
        self.send_confirmation_email(user)
        return None

    def send_confirmation_email(self, user: User):
        handler = ConfirmationEmailHandler(user=user)

        handler.send_email(
            subject=None,
            message=None,
            recipient_list=[user.email]
        )

    def send_password_reset_email(self, email: str):
        """Отправляет email со ссылкой для сброса пароля"""
        try:
            user = self.get_user(email)
        except User.DoesNotExist:
            # Не раскрываем, существует ли пользователь (безопасность)
            return None

        # Отправляем email
        handler = PasswordResetHandler(email=user.email)
        handler.reset_password()
        return None

def full_logout(request):
    response = Response({"detail": _("Successfully logged out.")}, status=status.HTTP_200_OK)
    auth_cookie_name = settings.REST_AUTH['JWT_AUTH_COOKIE']
    refresh_cookie_name = settings.REST_AUTH['JWT_AUTH_REFRESH_COOKIE']

    response.delete_cookie(auth_cookie_name)
    refresh_token = request.COOKIES.get(refresh_cookie_name)
    if refresh_cookie_name:
        response.delete_cookie(refresh_cookie_name)
    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
    except KeyError:
        response.data = {"detail": _("Refresh token was not included in request data.")}
        response.status_code = status.HTTP_401_UNAUTHORIZED
    except (TokenError, AttributeError, TypeError) as error:
        if hasattr(error, 'args'):
            if 'Token is blacklisted' in error.args or 'Token is invalid or expired' in error.args:
                response.data = {"detail": _(error.args[0])}
                response.status_code = status.HTTP_401_UNAUTHORIZED
            else:
                response.data = {"detail": _("An error has occurred.")}
                response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        else:
            response.data = {"detail": _("An error has occurred.")}
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    else:
        message = _(
            "Neither cookies or blacklist are enabled, so the token "
            "has not been deleted server side. Please make sure the token is deleted client side."
        )
        response.data = {"detail": message}
        response.status_code = status.HTTP_200_OK
    return response
