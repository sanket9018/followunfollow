# views.py
from rest_framework.generics import GenericAPIView
from rest_framework import status
from django.shortcuts import render, HttpResponseRedirect
from django.urls import reverse_lazy, reverse
from django.views.generic import CreateView
from django.views import View
from django.contrib.auth import login
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.views import LoginView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.http import urlsafe_base64_decode
from django.db import transaction
from . serializers import *
from django.shortcuts import (
    redirect,
    get_object_or_404
)

from django.contrib.auth import (
    login,
    logout,
    authenticate
)


from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated
)

from followunfollow.utils import (
    get_global_success_messages,
    get_global_error_messages,
    get_response_schema,
    get_tokens_for_user,
    send_forgot_password_email_business_user,
    generate_auth_token,
    send_auth_token_email,
    wrong_login_attempt,
    send_verification_email,
    get_serializer_error_msg,
    custom_token_generator,
)


from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from .models import UserProfile
from django.shortcuts import render


class UserLogin(GenericAPIView):

    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )
    )
    def post(self, request):

        data = request.data

        username = data["username"]

        password = data["password"]

        user = authenticate(request=request, username=username, password=password)

        if user == None:

            return get_response_schema(get_global_error_messages('NOT_FOUND'), get_global_error_messages('BAD_REQUEST'), status.HTTP_404_NOT_FOUND)
        
        if not user.is_active:

            return get_response_schema(get_global_error_messages('USER_NOT_ACTIVE'), get_global_error_messages('BAD_REQUEST'), status.HTTP_403_FORBIDDEN)
        
      
        login(request, user)
        
        refresh, access = get_tokens_for_user(user) 

        data.pop('password', None)

        result = data

        result["refresh"] = refresh

        result["access"] = access

        return get_response_schema(result, get_global_success_messages('LOGGED_IN'), status.HTTP_200_OK)
    

class UserLogout(GenericAPIView):
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body = openapi.Schema(
            type = openapi.TYPE_OBJECT,
            properties = {
                'refresh': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )
    )
    def post(self, request):

        try:
            refresh_token = RefreshToken(request.data['refresh'])

            refresh_token.blacklist()

            logout(request) 

            return get_response_schema({}, get_global_success_messages('LOGGED_OUT'), status.HTTP_200_OK)

        except:

            return get_response_schema(get_global_error_messages('INVALID_REFRESH_TOKEN'), get_global_error_messages('BAD_REQUEST'),status.HTTP_400_BAD_REQUEST)
        

# def follow_user(request, user_id):
#     user_to_follow = get_object_or_404(UserProfile, id=user_id)
#     user_profile = request.user.profile
#     user_profile.follow(user_to_follow.user)
#     return JsonResponse({'status': 'success'})


# def unfollow_user(request, user_id):
#     user_to_unfollow = get_object_or_404(UserProfile, id=user_id)
#     user_profile = request.user.profile
#     user_profile.unfollow(user_to_unfollow.user)
#     return JsonResponse({'status': 'success'})

# profile.html

def profile_view(request):
    # Retrieve the current user's profile
    user_profile = UserProfile.objects.get(user=request.user)
    
    # Retrieve the followers and following lists
    following = user_profile.followers.all()
    
    # Get the users that the logged-in user is following
    followers = request.user.following.all()
    
    # Create a context dictionary with the data
    context = {
        'user_profile': user_profile,
        'followers': followers,
        'following': following,
    }
    
    # Render the template with the context
    return render(request, 'profile.html', context)

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import UserProfile
from .serializers import UserProfileSerializer, UserSerializer

class FollowUser(APIView):

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        ),
        operation_description="Endpoint to follow user.",
        responses={200: "OK"},
    )
    def post(self, request):
        userid = request.data['user_id']
        # Get or create user profile
        user_profile, created = UserProfile.objects.get_or_create(user=request.user)

        # Retrieve the user to follow
        user_to_follow = User.objects.filter(pk=userid).first()

        if user_to_follow is None:
            return get_response_schema({}, get_global_error_messages('DATA_NOT_FOUND'), status.HTTP_404_NOT_FOUND)
        
        user_profile.follow(user_to_follow)
                
        return get_response_schema({}, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED)


class UnfollowUser(APIView):
    def post(self, request, user_id):
        user_profile = request.user.profile
        user_to_unfollow = User.objects.get(pk=user_id)
        user_profile.unfollow(user_to_unfollow)
        return Response(status=status.HTTP_200_OK)
    
class FollowersList(APIView):
    def get(self, request):
        followers = User.objects.filter(profile__following=request.user)
        serializer = UserSerializer(followers, many=True)
        return Response(serializer.data)
    
class FollowingList(APIView):
    def get(self, request):
        following = request.user.profile.following.all()  # Access following through the UserProfile model
        serializer = UserSerializer(following, many=True)
        return Response(serializer.data)