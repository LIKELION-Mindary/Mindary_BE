"""         import        """
import os
import requests
import jwt
import string
import random

from django.utils import timezone
from datetime import timedelta
from django.shortcuts import render
from rest_framework import status
from dotenv import load_dotenv
load_dotenv()

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import User, EmailVerification
from accounts.serializers import KakaoLoginRequestSerializer, KakaoRegisterRequestSerializer
from accounts.serializers import EmailVerificationSendSerializer, EmailVerificationCheckSerializer, OriginalRegistrationSerializer
from django.http import HttpResponse
from django.core.mail import send_mail

from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from django.views.decorators.csrf import csrf_exempt

import logging
logger = logging.getLogger('django')

"""
      < Kakao Login >
"""
def exchange_kakao_access_token(access_code):
		# access_code : 프론트가 넘겨준 인가 코드
		
    token = requests.post(
        'https://kauth.kakao.com/oauth/token',
        headers={
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
        },
        data={
            'grant_type': 'authorization_code',
            'client_id': os.environ.get('KAKAO_REST_API_KEY'),
            'redirect_uri': os.environ.get('KAKAO_REDIRECT_URI'),
            'code': access_code,
        },
    )

	# 300번대 이상이면 다른 조치
    # if token.status_code >= 300:
    #     return Response({'detail': 'Access token exchange failed'}, status=status.HTTP_401_UNAUTHORIZED)
    if token.status_code >= 300:
        logger.error(f"Failed to exchange token: {token.status_code} {token.text}")
        return Response({'detail': 'Access token exchange failed'}, status=token.status_code)
    return token.json()

def extract_kakao_email(kakao_data):
		# 응답으로 받은 id_token 값 가져오기
    id_token = kakao_data.get('id_token', None)
    if id_token is None:
        logger.error("ID token is missing from Kakao response.")
        return Response({'detail': 'Missing ID token'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if id_token is None: # 없으면 예외 처리
        logger.error("ID token is missing from Kakao response.")
        return Response({'detail': 'Missing ID token'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # JWT 키 가져오기 - 서명 검증에 필요한 키
    jwks_client = jwt.PyJWKClient(os.environ.get('KAKAO_OIDC_URI'))
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    # JWT의 알고리즘 가져오기 (JWT 헤더에 포함된 정보) - 서명 검증에 필요
    signing_algol = jwt.get_unverified_header(id_token)['alg']

    try: # id_token=jwt의 페이로드에는 사용자 인증 정보들이 담겨 있음
        payload = jwt.decode( # JWT 디코딩 -> 페이로드 추출
            id_token,
            key=signing_key.key,               # JWT의 서명 검증
            algorithms=[signing_algol],        # |-> 유효한지 확인
            audience=os.environ.get('KAKAO_REST_API_KEY'),
        )
        email = payload.get('email')
        if not email:
            logger.error("Email not found in JWT payload.")
            return Response({'detail': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)
        return email

    except jwt.ExpiredSignatureError:
        logger.error("The token has expired.")
        return Response({'detail': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        logger.error("Invalid JWT token.")
        return Response({'detail': 'OIDC auth failed(invalid token)'}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        logger.error(f"Unexpected error decoding token: {str(e)}")
        return Response({'detail': 'Error decoding token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_login(request):
    serializer = KakaoLoginRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    data = serializer.validated_data
    
    # 인가 코드로 토큰 발급 -> 닉네임 추출
    kakao_data = exchange_kakao_access_token(data['access_code'])
    email = extract_kakao_email(kakao_data)

    try: # 해당 email을 가진 user가 있는지 확인
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'detail': '존재하지 않는 사용자입니다.'}, status=404)

		# user login 처리

		# user 확인 했으므로 우리 토큰 발행
    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    }, status=status.HTTP_200_OK)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_register(request):
    serializer = KakaoRegisterRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    data = serializer.validated_data

    kakao_data = exchange_kakao_access_token(data['access_code'])
    email = extract_kakao_email(kakao_data)
    nickname = data.get('nickname')

    if not nickname:
        return Response({"error": "Nickname is required"}, status=status.HTTP_400_BAD_REQUEST)

	# 이미 존재하는 사용자 예외처리
    ok = False
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        ok = True
    if not ok:
        return Response({'detail': '이미 등록 된 사용자입니다.'}, status=400)

    # new 사용자 : 인증하고 우리의 토큰 발급
    user = User.objects.create_user(email=email, nickname=nickname)
    
    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    }, status=status.HTTP_200_OK)


# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def kakao_logout(request): #토큰 만료 
#     KAKAO_REST_API_KEY = os.environ.get('KAKAO_REST_API_KEY')
#     LOGOUT_REDIRECT_URI = 'http://localhost:3000/mindary'
#     logout_response = requests.get(f'https://kauth.kakao.com/oauth/logout?client_id=${KAKAO_REST_API_KEY}&logout_redirect_uri=${LOGOUT_REDIRECT_URI}')
#     if logout_response.status_code == 200:
#         return Response({'detail': '로그아웃되었습니다.'}, status=status.HTTP_200_OK)
#     else:
#         return Response({'detail': '로그아웃 실패'}, status=status.HTTP_400_BAD_REQUEST)
@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify(request):
    return Response({'datail': 'Token is verified.'}, status=200)



"""
      < Original Login >
"""
# 새 비밀번호 생성 함수
def create_new_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# 새 비밀번호 전송 함수
def send_new_password(email, new_password):
    subject = '마인더리(mindary) 새 비밀번호 안내 이메일입니다.'
    message = f'안녕하세요. 마인더리(mindary)입니다. \n 회원님의 새 비밀번호는 {new_password} 입니다.'
    email_from = 'mdy3722@gmail.com'
    recipient_list = [email,]

    send_mail(subject, message, email_from, recipient_list)

# 코드 전송 함수
def send_code(email, code):
    subject = '마인더리(mindary) 인증코드 안내 이메일입니다.'
    message = f'안녕하세요. 마인더리(mindary)입니다. \n 인증코드를 확인해주세요. \n {code} \n 인증코드는 이메일 발송 시점부터 3분동안 유효합니다.'
    email_from = 'mdy3722@gmail.com'
    recipient_list = [email]

    send_mail(subject, message, email_from, recipient_list)

# 인증 코드 전송하기
@api_view(['POST'])
def send_verification_code(request):
    serializer = EmailVerificationSendSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']

        # 이메일이 이미 등록된 사용자에게 속해 있는지 확인
        if User.objects.filter(email=email).exists():
            return Response({'error': '이미 존재하는 회원입니다.'}, status=status.HTTP_400_BAD_REQUEST)
        
        code = f"{random.randint(1000, 9999)}"
        expires_at = timezone.now() + timedelta(minutes=5)
        EmailVerification.objects.create(email=email, code=code, expires_at=expires_at)

        send_code(email, code)

        return Response({'message': 'Verification code sent to email.'}, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 인증 코드 확인하기
@api_view(['POST'])
def verify_code(request):
    serializer = EmailVerificationCheckSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']
        try:
            verification = EmailVerification.objects.get(email=email, code=code)
            if verification.is_expired():
                return Response({'error': 'Verification code expired.'}, status=status.HTTP_400_BAD_REQUEST)
            verification.delete()
            return Response({'message': 'Verification code is valid.'}, status=status.HTTP_200_OK)
        except EmailVerification.DoesNotExist:
            return Response({'error': 'Invalid verification code.'}, status=status.HTTP_401_UNAUTHORIZED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 회원가입
@api_view(['POST'])
def original_register(request):
    serializer = OriginalRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({'message': '회원가입에 성공했습니다!'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 로그인
@api_view(['POST'])
def original_login(request):
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email:
        return Response({'error': '이메일을 입력해 주세요'}, status=status.HTTP_400_BAD_REQUEST)
    if not password:
        return Response({'error': '비밀번호를 입력해 주세요'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': '이메일이 잘못되었습니다.'}, status=status.HTTP_401_UNAUTHORIZED)

    user = authenticate(email=email, password=password)
    
    if user is None:
        return Response({'error': '비밀번호가 잘못되었습니다.'}, status=status.HTTP_401_UNAUTHORIZED)

    refresh_token = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh_token.access_token),
        'refresh_token': str(refresh_token),
    }, status=status.HTTP_200_OK)

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def original_logout(request):
    try:
        refresh_token = request.data.get('refresh_token')
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({'message': '로그아웃 성공!'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

# 새 비밀번호 
@api_view(['POST'])
def reset_password(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': '존재하지 않는 유저입니다.'}, status=status.HTTP_404_NOT_FOUND)

    new_password = create_new_password()
    user.set_password(new_password)
    user.save()
    
    send_new_password(email, new_password)

    return Response({'message': '새로운 비밀번호가 전송되었습니다.'}, status=status.HTTP_200_OK)



"""
      < 토큰 갱신 > - 아직 url 및 연결 X
"""
# 토큰 갱신 -> refresh를 request로 보내면 access 토큰을 새로 발급해줌
@api_view(['POST'])
def token_refresh(request):
    refresh_token = request.data.get('refresh_token')
    
    if not refresh_token:
        return Response({'error': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        refresh = RefreshToken(refresh_token)
        access_token = str(refresh.access_token)
        return Response({'access_token': access_token, 'refresh_token': str(refresh)}, status=status.HTTP_200_OK)
    except TokenError as e:
        return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)