from rest_framework import serializers
from .models import Client, AdminUser,ApproversCategory

class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = "__all__"

class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminUser
        exclude = [ 'password', 'last_login', 'is_superuser', 'changed_by', 'created_by', 'created_at', 'changed_at' ]

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        meta = ApproversCategory
        fields = "__all__"