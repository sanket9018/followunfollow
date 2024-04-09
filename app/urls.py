# urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import profile_view

from app.views import *



urlpatterns = [
    path('profile_view/', profile_view, name='profile_view'),

    path('login/', UserLogin.as_view(), name='login'),
    path('logout/', UserLogout.as_view(), name='logout'),
    path('profile_view/', profile_view, name='profile_view'),

    path('refreshtoken/', TokenRefreshView.as_view(), name='token_refresh'),

    path('follow/', FollowUser.as_view(), name='follow_user'),
    path('unfollow/<int:user_id>/', UnfollowUser.as_view(), name='unfollow_user'),
    path('followers/', FollowersList.as_view(), name='followers_list'),
    path('following/', FollowingList.as_view(), name='following_list'),

]
