from rest_framework import serializers
<<<<<<< Updated upstream
from .models import Client, AdminUser,ApproversCategory, Task

=======
from .models import Client, AdminUser,ApproversCategory
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
>>>>>>> Stashed changes
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
        model = ApproversCategory
        fields = "__all__"

<<<<<<< Updated upstream
class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = "__all__"
        read_only_fields = ['approver', 'approval_status', 'is_approval_needed', 'approved_by']
=======
class SimpleTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'
    
    def validate(self,attrs):
        email = attrs.get('email', '').strip().lower()
        password = attrs.get('password')

        user = authenticate(request=self.context.get('request'),email=email,password=password)

        if not user:
            raise AuthenticationFailed('Invalid email or password. Please try again.')

        if not user.is_active:
            raise AuthenticationFailed('Your account is inactive. Please contact administrator.')
        
        refresh = self.get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
>>>>>>> Stashed changes
