from django.urls import path
from .views import *

urlpatterns = [
    # Original_Login
    path('original/login', original_login),
    path('original/register', original_register),
    path('original/logout', original_logout),
    path('original/send-code', send_verification_code),
    path('original/verify-code', verify_code),
    path('original/new-password', reset_password),

    # Kakao_Login
    path('kakao/login', kakao_login),
    path('kakao/register', kakao_register),
    #path('kakao/logout', original_logout),
    path('kakao/verify', verify),
]