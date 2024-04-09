# serializers.py
from django.contrib.auth.models import User

from rest_framework import serializers
from .models import UserProfile

class FollowSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()

class UnfollowSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()



class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('user', 'following')


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username')
