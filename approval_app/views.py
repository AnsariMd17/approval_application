from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from .models import AdminUser, Client, Task, ApproversCategory
from .forms import AdminUserForm, ClientForm
from django.db.models import Q 
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from notifications.views import create_notification
from django.utils import timezone

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import *
from .models import *

from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

def create_task_history(task, approval_status, task_status, created_by_user):
    """
    Helper function to create task history entries
    """
    TaskHistory.objects.create(
        task=task,
        approval_status=approval_status,
        task_status=task_status,
        created_by=created_by_user,
        changed_by=created_by_user
    )


def is_admin(user):
    return user.is_authenticated and user.is_super_user and user.is_approver

def is_approver_only(user):
    return user.is_authenticated and user.is_approver and not user.is_super_user

@login_required
def dashboard(request):
    admin_users = AdminUser.objects.all()
    clients = Client.objects.all().order_by('-created_at')

    show_add_btn = request.user.is_super_user and request.user.is_approver
    is_admin = show_add_btn  # True if user is both super_user and approver

    context = {
        'user': request.user,
        'total_admins': admin_users.filter(is_super_user=True, is_approver=True).count(),
        'total_clients': clients.count(),
        'total_approvers': admin_users.filter(is_approver=True, is_super_user=False).count(),
        'total_super_users': admin_users.filter(is_super_user=True).count(),
        'clients': clients,
        'show_add_btn': show_add_btn,
        'is_admin': is_admin,
        'is_approver_only': request.user.is_approver and not request.user.is_super_user,
    }
    return render(request, 'approval_app/dashboard.html', context)

@login_required
def admin_user_list(request):
    admin_users = AdminUser.objects.order_by('-created_at')
    search = request.GET.get('search')
    if search:
        admin_users = admin_users.filter(
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search) |
            Q(email__icontains=search) |
            Q(username__icontains=search)
        )
    paginator = Paginator(admin_users, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'approval_app/admin_user_list.html', {
        'page_obj': page_obj,
        'search': search
    })

@login_required
def client_list(request):
    clients = Client.objects.order_by('-created_at')
    search = request.GET.get('search')
    if search:
        clients = clients.filter(
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search) |
            Q(program__icontains=search) |
            Q(mobile_number__icontains=search)
        )
    program_filter = request.GET.get('program')
    if program_filter:
        clients = clients.filter(program__icontains=program_filter)
    paginator = Paginator(clients, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    programs = Client.objects.values_list('program', flat=True).distinct().order_by('program')
    return render(request, 'approval_app/client_list.html', {
        'page_obj': page_obj,
        'search': search,
        'programs': programs,
        'program_filter': program_filter
    })

@login_required
def add_admin_user(request):
    """Add new admin user"""
    if request.method == 'POST':
        form = AdminUserForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Admin user added successfully!')
            return redirect('admin_user_list')
    else:
        form = AdminUserForm()
    
    return render(request, 'approval_app/add_admin_user.html', {'form': form})

@login_required
def edit_admin_user(request, user_id):
    """Edit admin user"""
    user = get_object_or_404(AdminUser, id=user_id)
    
    if request.method == 'POST':
        form = AdminUserForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Admin user updated successfully!')
            return redirect('admin_user_list')
    else:
        form = AdminUserForm(instance=user)
    
    return render(request, 'approval_app/edit_admin_user.html', {'form': form, 'user': user})


class AddClientAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ClientSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@login_required
def delete_admin_user(request, user_id):
    """Delete admin user"""
    user = get_object_or_404(AdminUser, id=user_id)
    if request.method == 'POST':
        user.delete()
        messages.success(request, 'Admin user deleted successfully!')
        return redirect('admin_user_list')
    return render(request, 'approval_app/confirm_delete.html', {
        'object': user,
        'object_type': 'Admin User',
        'cancel_url': 'admin_user_list'
    })




from django.contrib.auth import authenticate, login, logout
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

@csrf_exempt
def admin_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_active:
            # Only allow admins (not clients)
            if user.is_approver or user.is_super_user:
                login(request, user)
                # JWT token generation
                refresh = RefreshToken.for_user(user)
                response = redirect('dashboard')
                response.set_cookie('jwt', str(refresh.access_token), httponly=True)
                return response
            else:
                messages.error(request, 'You are not authorized to login here.')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'approval_app/login.html')

def admin_signup(request):
    if request.method == 'POST':
        form = AdminUserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.is_active = True
            # You may want to require admin approval for new users; set is_approver/is_super_user as needed
            user.save()
            messages.success(request, 'Admin account created. Please log in.')
            return redirect('admin_login')
    else:
        form = AdminUserForm()
    return render(request, 'approval_app/sign_up.html', {'form': form})

@login_required
def admin_logout(request):
    logout(request)
    response = redirect('admin_login')
    response.delete_cookie('jwt')
    return response



from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken
from datetime import datetime
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        try:
            user = request.user
            token_value = request.META.get('HTTP_AUTHORIZATION').split('Bearer')[-1]
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            if not token_value or token_value is None:
                return Response({"error: token cannot be empty"},status = status.HTTP_400_BAD_REQUEST)
            
            try:
                token = AccessToken(token_value)
                jti = token['jti']
                exp_timestamp = token['exp']
                expires_at = datetime.fromtimestamp(exp_timestamp)
            except Exception as e:
                return Response({"error": f"Invalid token format: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
           
            token_object = OutstandingToken()
            token_object.jti = jti
            token_object.token = str(token_value)
            token_object.user_id = request.user.id
            token_object.expires_at = expires_at
            token_object.save()
            
            blacklist_token = BlacklistedToken(token=token_object)
            blacklist_token.save()

            return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
        except KeyError:
            return Response({"detail": "Refresh token not provided."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"detail": "Token is invalid or expired."}, status=status.HTTP_400_BAD_REQUEST)
        
        # user = request.user

        # refresh_token = request.data.get("refresh")
        # if refresh_token:
        #     token = RefreshToken(refresh_token)
        #     token.blacklist()
        
        # return Response({"detail": "Logged out successfully."}, status=status.HTTP_200_OK)
class EditClientAPI(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, client_id):
        # You can customize permission check as needed
        user = request.user
        if not (getattr(user, "is_super_user", False) and getattr(user, "is_approver", False)):
            return Response({"detail": "You do not have permission to edit clients."}, status=status.HTTP_403_FORBIDDEN)
        client = get_object_or_404(Client, id=client_id)
        serializer = ClientSerializer(client, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DeleteClientAPI(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, client_id):
        user = request.user
        if not (getattr(user, "is_super_user", False) and getattr(user, "is_approver", False)):
            return Response({"detail": "You do not have permission to delete clients."}, status=status.HTTP_403_FORBIDDEN)
        client = get_object_or_404(Client, id=client_id)
        client.delete()
        return Response({"detail": "Client deleted successfully!"}, status=status.HTTP_204_NO_CONTENT)
    

class ClientListDetailAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, client_id=None):
        if client_id is not None:
            # Return a single client
            try:
                client = Client.objects.get(id=client_id)
            except Client.DoesNotExist:
                return Response({"detail": "Client not found."}, status=status.HTTP_404_NOT_FOUND)
            serializer = ClientSerializer(client)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            # List all clients with optional search & program filter
            clients = Client.objects.order_by('-created_at')
            search = request.GET.get('search')
            if search:
                clients = clients.filter(
                    Q(first_name__icontains=search) |
                    Q(last_name__icontains=search) |
                    Q(program__icontains=search) |
                    Q(mobile_number__icontains=search)
                )
            program_filter = request.GET.get('program')
            if program_filter:
                clients = clients.filter(program__icontains=program_filter)

            paginator = PageNumberPagination()
            paginator.page_size = 10  # or set as desired
            result_page = paginator.paginate_queryset(clients, request)
            serializer = ClientSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)





# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def add_client(request):
#     # Only admins can add a client
#     if not (getattr(request.user, 'is_super_user', False) and getattr(request.user, 'is_approver', False)):
#         messages.error(request, "Only admins can add a client.")
#         return redirect('dashboard')

#     if request.method == 'POST':
#         form = ClientForm(request.POST)
#         if form.is_valid():
#             client = form.save(commit=False)
#             action = request.POST.get('action')
#             if action == "save":
#                 # Save Directly: self-approved
#                 client.approval_needed = False
#                 client.approval_status = "self-approved"   # This must match your STATUS_CHOICES now
#                 client.is_approved_client = True
#             elif action == "save_approval":
#                 # Save & Send Approval Request
#                 client.approval_needed = True
#                 client.approval_status = "pending"
#                 client.is_approved_client = False
#             else:
#                 pass
#             client.save()
#             messages.success(request, 'Client added successfully!')
#             return redirect('dashboard')
#         else:
#             messages.error(request, "Please correct the errors below.")
#     else:
#         form = ClientForm()
#     return render(request, 'approval_app/add_client.html', {'form': form})




# @login_required
# def edit_client(request, client_id):
#     if not (request.user.is_super_user and request.user.is_approver):
#         messages.error(request, "You do not have permission to edit clients.")
#         return redirect('dashboard')
#     client = get_object_or_404(Client, id=client_id)
#     if request.method == 'POST':
#         form = ClientForm(request.POST, instance=client)
#         if form.is_valid():
#             form.save()
#             messages.success(request, 'Client updated successfully!')
#             return redirect('dashboard')
#     else:
#         form = ClientForm(instance=client)
#     return render(request, 'approval_app/edit_client.html', {'form': form, 'client': client})

# @login_required
# def delete_client(request, client_id):
#     if not (request.user.is_super_user and request.user.is_approver):
#         messages.error(request, "You do not have permission to delete clients.")
#         return redirect('dashboard')
#     client = get_object_or_404(Client, id=client_id)
#     if request.method == 'POST':
#         client.delete()
#         messages.success(request, 'Client deleted successfully!')
#         return redirect('dashboard')
#     return render(request, 'approval_app/confirm_delete.html', {
#         'object': client,
#         'object_type': 'Client',
#         'cancel_url': 'dashboard'
#     })


# @login_required
# def approve_client(request, client_id):
#     if not is_approver_only(request.user) and not is_admin(request.user):
#         messages.error(request, "You don't have permission to approve clients.")
#         return redirect('dashboard')
#     client = get_object_or_404(Client, id=client_id)
#     if request.method == 'POST':
#         form = ClientApprovalForm(request.POST, instance=client)
#         if form.is_valid():
#             status = form.cleaned_data['approval_status']
#             reason = form.cleaned_data.get('rejection_reason', '')
#             if status == 'approved':
#                 client.approval_status = 'approved'
#                 client.is_approved_client = True
#                 client.rejection_reason = ''
#                 messages.success(request, 'Client approved!')
#             elif status == 'rejected':
#                 client.approval_status = 'rejected'
#                 client.is_approved_client = False
#                 client.rejection_reason = reason
#                 messages.success(request, 'Client rejected!')
#             client.save()
#             return redirect('dashboard')
#     else:
#         form = ClientApprovalForm(instance=client)
#     return render(request, 'approval_app/approve_client.html', {'form': form, 'client': client})

from rest_framework import generics
class CategoryListCreate(generics.ListCreateAPIView):
    queryset = ApproversCategory.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        category = serializer.save()
        approvers = category.approvers.all()
        
        # Create notifications for each approver
        for approver in approvers:
            message = f"A new category '{category.category_name}' has been created and you have been assigned as an approver."
            redirect_url = f"/categories/view/{category.id}/"  
            
            # Call your utility function to create notification
            create_notification(
                message=message,
                redirect_url=redirect_url,
                recipient_id=approver.id,
                created_by=self.request.user
            )

            # Send stage approver notifications only for those with approval needed
            for stage in getattr(serializer, '_new_stages', []):
                if stage.stage_approval_needed:
                    for approver in stage.stage_approvers.all():
                        stage_message = (
                            f"A New stage '{stage.stage_name}' has been activated and it has been assigned to the category of "
                            f"'{category.category_name}' requesting your approval"
                        )
                        stage_redirect_url = f"/categories/{category.id}/stages/{stage.id}/"
                        create_notification(
                            message=stage_message,
                            redirect_url=stage_redirect_url,
                            recipient_id=approver.id,
                            created_by=self.request.user
                        )
        
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            {
                'message': 'Category created successfully and notifications sent to approvers',
                'data': serializer.data
            }, 
            status=status.HTTP_201_CREATED, 
            headers=headers
        )

class CategoryRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    queryset = ApproversCategory.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def perform_update(self, serializer):
        category = serializer.save()
        
        for stage, approver_ids in getattr(serializer, "_notified_stage_approvers", []):
            for approver_id in approver_ids:
                approver = AdminUser.objects.get(id=approver_id)
                message = (
                    f"You have been assigned as approver to the stage '{stage.stage_name}' "
                    f"in category '{category.category_name}'."
                )
                redirect_url = f"/categories/{category.id}/stages/{stage.id}/"
                create_notification(
                    message=message,
                    redirect_url=redirect_url,
                    recipient_id=approver.id,
                    created_by=self.request.user
                )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(
            {
                'message': 'Category and stages updated successfully. Notifications sent as needed.',
                'data': serializer.data
            },
            status=status.HTTP_200_OK
        )

class AdminListDetailAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, admin_id=None):
        if admin_id is not None:
            try:
                admin = AdminUser.objects.get(id=admin_id)
            except AdminUser.DoesNotExist:
                return Response({"detail": "Admin not found."}, status=status.HTTP_404_NOT_FOUND)
            serializer = AdminUserSerializer(admin)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            admins = AdminUser.objects.all().order_by('id')
            paginator = PageNumberPagination()
            paginator.page_size = 10
            result_page = paginator.paginate_queryset(admins, request)
            serializer = AdminUserSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)

from django.db import transaction
class TaskListCreate(generics.ListCreateAPIView):
    """
    API view to retrieve list of tasks or create a new task.
    """
    queryset = Task.objects.all()
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        """
        Return appropriate serializer based on request method
        """
        if self.request.method == 'POST':
            return TaskCreateSerializer
        else:
            return TaskSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        """
        Custom create method to handle task creation with approval logic
        """
        
        serializer = TaskCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data
        
        category_id = validated_data.get('category')
        if not category_id:
            return Response(
                {"detail": "Category ID is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            category_instance = ApproversCategory.objects.get(id=category_id.id)
        except ApproversCategory.DoesNotExist:
            return Response(
                {"detail": "Category not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        is_approval_needed = validated_data.get('is_approval_needed', False)
        if is_approval_needed:
            approval_status = 'Pending'
        else:
            approval_status = 'Self-Approved'
        
        task = Task.objects.create(
            client_id=validated_data['client_id'],
            task=validated_data['task'],
            task_status=validated_data.get('task_status', 'pending'),
            task_description=validated_data.get('task_description', ''),
            task_due_date=validated_data.get('task_due_date'),
            task_completed_date=validated_data.get('task_completed_date'),
            is_approval_needed=is_approval_needed,
            category=category_instance,
            approval_status=approval_status,
            created_by=request.user,
            created_at = timezone.now()
        )
        
        if is_approval_needed:
            category_approvers = category_instance.approvers.all()
            if not category_approvers.exists():
                return Response(
                    {"detail": "No approvers found for the selected category"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            task_approvers = [
                TaskApprover(
                    Task=task,
                    approver=approver,
                    is_approved_status='Pending',
                    created_by=request.user,
                    created_at=timezone.now()
                )
                for approver in category_approvers
            ]
            TaskApprover.objects.bulk_create(task_approvers)

            stages_qs = category_instance.stages.all().order_by('id')
            if not stages_qs.exists():
                return Response(
                    {"detail": "No stages found for the selected category"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            first_stage = stages_qs.first()
            if first_stage and is_approval_needed:
                first_stage_approvers = first_stage.stage_approvers.all()

                if not first_stage_approvers.exists():
                    return Response(
                        {"detail": "No approvers found for the first stage in this category"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

                for approver in first_stage_approvers:
                    message = (
                        f"The new task has been assigned in the category of {category_instance.category_name} "
                        f"and is requesting your approval for the first stage: {first_stage.stage_name}"
                    )
                    redirect_url = f"/tasks/{task.id}?mode=approve"
                    create_notification(
                        message=message,
                        redirect_url=redirect_url,
                        recipient_id=approver.id,
                        created_by=request.user
                    )
        
        create_task_history(
            task=task,
            approval_status=approval_status.lower(), 
            task_status=task.task_status,
            created_by_user=request.user
        )
        
        response_serializer = TaskSerializer(task)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

class TaskRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    """
    API view to retrieve, update, or delete a task instance.
    Only allows editing of selected fields.
    Creates a task history record if approval_status is rejected.
    """
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def update(self, request, *args, **kwargs):
        instance = self.get_object()

        # Extract and restrict data to only allowed fields
        allowed_fields = [
            'client_id', 'task', 'task_status',
            'task_description', 'task_due_date', 'task_completed_date'
        ]
        data = {
            field: value for field, value in request.data.items()
            if field in allowed_fields
        }

        partial = request.method == "PATCH"
        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Re-fetch the updated instance
        updated_instance = self.get_object()

        # Create TaskHistory record if approval_status is "rejected"
        if updated_instance.approval_status.lower() == "rejected":
            updated_instance.approval_status = 'Pending'
            updated_instance.save()
            
            TaskHistory.objects.create(
                task=updated_instance,
                approval_status='Resubmitted',
                task_status=updated_instance.task_status,
                created_by=request.user,
                created_at=timezone.now()
            )
            
            category_approvers = updated_instance.category.approvers.all()
            for approver in category_approvers:
                message = f"The rejected task '{updated_instance.task}' has been Resubmitted and requires your approval"
                redirect_url = f"/tasks/{updated_instance.id}?mode=approve"
                
                # Send notification to each approver
                create_notification(
                    message=message,
                    redirect_url=redirect_url,
                    recipient_id=approver.id,
                    created_by=request.user
                )

        return Response(serializer.data, status=status.HTTP_200_OK)
    
# from rest_framework.views import APIView
# class UpdateApprovalTaskView(APIView):
#     permission_classes = [IsAuthenticated]
#     def put(self, request, task_id):
#         client_id = request.data.get('client_id')
#         approval_status = request.data.get('approval_status')
#         current_user_id = request.user.id
#         if not client_id or not task_id:
#             return Response({'error': 'Client ID and task ID are required.'}, status=status.HTTP_400_BAD_REQUEST)
        
#         if approval_status.lower() not in ["approve", "reject"]:
#             return Response(
#                 {"detail": "Invalid approval status. approval_status must be either 'approve' or 'reject'."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
        
#         try:
#             client = Client.objects.get(id=client_id)
#             task = Task.objects.get(id=task_id, client_id=client)
#             task_approver = TaskApprover.objects.get(Task=task, approver=current_user_id)
#         except Client.DoesNotExist:
#             return Response({'error': 'Client not found.'}, status=status.HTTP_404_NOT_FOUND)
#         except Task.DoesNotExist:
#             return Response({'error': 'Task not found.'}, status=status.HTTP_404_NOT_FOUND)
#         except TaskApprover.DoesNotExist:
#             return Response({'error': 'Invalid approver for this task'}, status=status.HTTP_404_NOT_FOUND)
#         except Exception as e:
#             return Response({'error': 'An unexpected error occurred. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#         if task.approval_status in ['Approved']:
#             return Response({'error': f'This task has already been Approved'}, status=status.HTTP_400_BAD_REQUEST)
        
#         approvers_for_tasks = TaskApprover.objects.filter(Task=task).exclude(approver__isnull=True)
#         all_approver_ids = [ta.approver.id for ta in approvers_for_tasks if ta.approver]

#         if approval_status == "approve":
#             task.approval_status = 'Approved'
#             task_approver.is_approved_status = 'Approved'
#             task_approver.save()

#             # Send notification for approval
#             message = f"The Task {task.task} approved by one of the approver"
#             redirect_url = f"/tasks/view/{task.id}/"
            
#             # Send notification to the task creator
#             for approver_id in all_approver_ids:
#                 create_notification(
#                     message=message,
#                     redirect_url=redirect_url,
#                     recipient_id=approver_id,
#                     created_by=request.user
#                 )
            
#             # Create task history entry for approval
#             create_task_history(
#                 task=task,
#                 approval_status='Approved',
#                 task_status=task.task_status,
#                 created_by_user=request.user
#             )


#         elif approval_status == "reject":
#             task.approval_status = 'Rejected'
#             task_approver.is_approved_status = 'Rejected'
#             task_approver.save()

#             # Send notification for rejection
#             message = f"The Task {task.task} rejected by one of the approver"
#             redirect_url = f"/tasks/edit/{task.id}/"
            
#             # Send notification to the task creator
#             for approver_id in all_approver_ids:
#                 create_notification(
#                     message=message,
#                     redirect_url=redirect_url,
#                     recipient_id=approver_id,
#                     created_by=request.user
#                 )
            
#             # Create task history entry for rejection
#             create_task_history(
#                 task=task,
#                 approval_status='Rejected',
#                 task_status=task.task_status,
#                 created_by_user=request.user
#             )

#         else:
#             return Response({'error': 'Invalid approval status.'}, status=status.HTTP_400_BAD_REQUEST)

#         task.save()
#         serializer = TaskSerializer(task)
#         return Response({
#             'message': f'Task has been {task.approval_status.lower()}.',
#             'task': serializer.data}, status=status.HTTP_200_OK)

class SimpleTokenObtainPairView(TokenObtainPairView):
    serializer_class = SimpleTokenObtainPairSerializer

    # def post(self, request, *args, **kwargs):
    #     serializer = self.serializer_class(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     tokens = serializer.validated_data

    #     response = Response(
    #         {"message": "Login successful"},
    #         status=status.HTTP_200_OK
    #     )

    #     # Store access token in cookie (can be JS-readable or HttpOnly)
    #     response.set_cookie(
    #         key='access_token',
    #         value=tokens['access'],
    #         httponly=False,  # set to True if you want HttpOnly
    #         secure=True,
    #         samesite='Lax',
    #         max_age=5 * 60  # 5 minutes
    #     )

    #     # Store refresh token in HttpOnly cookie (secure)
    #     response.set_cookie(
    #         key='refresh_token',
    #         value=tokens['refresh'],
    #         httponly=True,
    #         secure=True,
    #         samesite='Lax',
    #         max_age=7 * 24 * 60 * 60  # 7 days
    #     )

    #     return response
@method_decorator(csrf_exempt, name='dispatch')
class SignupAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = AdminUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(request.data.get('password1'))
            user.is_active = True
            user.save()
            return Response({
                'message': 'User created successfully',
                'user': AdminUserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class UpdateApprovalTaskView(APIView):
    permission_classes = [IsAuthenticated]
    
    def put(self, request, task_id):
        client_id = request.data.get('client_id')
        approval_status = request.data.get('approval_status')
        stage_id = request.data.get('stage_id')
        stage_status = request.data.get('stage_status')
        stage_rejected_reason = request.data.get('stage_rejected_reason')
        current_user_id = request.user.id
        
        # Basic validation
        if not client_id or not task_id or not stage_id:
            return Response({'error': 'Client ID, task ID and stage ID are required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        if approval_status.lower() not in ["approve", "reject"]:
            return Response(
                {"detail": "Invalid approval status. approval_status must be either 'approve' or 'reject'."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            client = Client.objects.get(id=client_id)
            task = Task.objects.get(id=task_id, client_id=client)
            stage = Stage.objects.get(id=stage_id)
            stage_approver = StageApprover.objects.get(stage=stage, approver=current_user_id)
        except Client.DoesNotExist:
            return Response({'error': 'Client not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Task.DoesNotExist:
            return Response({'error': 'Task not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Stage.DoesNotExist:
            return Response({'error': 'Stage not found.'}, status=status.HTTP_404_NOT_FOUND)
        except StageApprover.DoesNotExist:
            return Response({'error': 'You are not authorized to approve/reject this stage.'}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({'error': 'An unexpected error occurred. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        
        current_time = timezone.now()
        
        if approval_status.lower() == "approve":
            # Update Stage model
            stage.stage_approval_status = 'Approved'
            stage.stage_approved_by = request.user
            stage.stage_approved_at = current_time
            
            # Update stage status if provided
            if stage_status:
                stage.stage_status = stage_status.lower()
            
            stage.save()
            
            # Update StageApprover model
            stage_approver.approval_status = 'Approved'
            stage_approver.save()
            
            # Update Task model approval status
            task.approval_status = 'Approved'
            task.save()
            
            # Update TaskApprover model (if exists for current user)
            try:
                task_approver_obj = TaskApprover.objects.get(Task=task, approver=current_user_id)
                task_approver_obj.is_approved_status = 'Approved'
                task_approver_obj.save()
            except TaskApprover.DoesNotExist:
                return Response({'error': 'Task Approver not found.'}, status=status.HTTP_404_NOT_FOUND)
            
            # Send notification for stage approval
            message = f"Stage '{stage.stage_name}' has been approved by one of the approvers"
            redirect_url = f"/tasks/view/{task.id}/"
            
            # Get all stage approvers for notification
            stage_approvers = StageApprover.objects.filter(stage=stage).exclude(approver__isnull=True)
            for sa in stage_approvers:
                create_notification(
                    message=message,
                    redirect_url=redirect_url,
                    recipient_id=sa.approver.id,
                    created_by=request.user
                )
            
            # Send notification to task approvers as well
            approvers_for_tasks = TaskApprover.objects.filter(Task=task).exclude(approver__isnull=True)
            all_approver_ids = [ta.approver.id for ta in approvers_for_tasks if ta.approver and ta.approver.id != current_user_id]
            for approver_id in all_approver_ids:
                create_notification(
                    message=f"The Task {task.task} approved via stage approval",
                    redirect_url=redirect_url,
                    recipient_id=approver_id,
                    created_by=request.user
                )
            
            # Create task history entry for stage approval
            create_task_history(
                task=task,
                approval_status='Approved',
                task_status=task.task_status,
                created_by_user=request.user
            )
            
            response_message = f"Stage '{stage.stage_name}' has been approved successfully."
            
        elif approval_status.lower() == "reject":
            # Update Stage model
            stage.stage_approval_status = 'Rejected'
            stage.stage_rejected_by = request.user
            stage.stage_rejected_at = current_time
            
            # Store rejection reason if provided
            if stage_rejected_reason:
                stage.stage_rejected_reason = stage_rejected_reason
            
            # Update stage status if provided
            if stage_status:
                stage.stage_status = stage_status.lower()
            
            stage.save()
            
            # Update StageApprover model
            stage_approver.approval_status = 'Rejected'
            stage_approver.save()
            
            # Update Task model approval status
            task.approval_status = 'Rejected'
            task.save()
            
            # Update TaskApprover model (if exists for current user)
            try:
                task_approver_obj = TaskApprover.objects.get(Task=task, approver=current_user_id)
                task_approver_obj.is_approved_status = 'Rejected'
                task_approver_obj.save()
            except TaskApprover.DoesNotExist:
                return Response({'error': 'Task Approver not found.'}, status=status.HTTP_404_NOT_FOUND)
            
            # Send notification for stage rejection
            message = f"Stage '{stage.stage_name}' has been rejected by one of the approvers"
            redirect_url = f"/tasks/edit/{task.id}/"
            
            # Get all stage approvers for notification
            stage_approvers = StageApprover.objects.filter(stage=stage).exclude(approver__isnull=True)
            for sa in stage_approvers:
                create_notification(
                    message=message,
                    redirect_url=redirect_url,
                    recipient_id=sa.approver.id,
                    created_by=request.user
                )
            
            # Send notification to task approvers as well
            approvers_for_tasks = TaskApprover.objects.filter(Task=task).exclude(approver__isnull=True)
            all_approver_ids = [ta.approver.id for ta in approvers_for_tasks if ta.approver and ta.approver.id != current_user_id]
            for approver_id in all_approver_ids:
                create_notification(
                    message=f"The Task {task.task} rejected via stage rejection",
                    redirect_url=redirect_url,
                    recipient_id=approver_id,
                    created_by=request.user
                )
            
            # Create task history entry for stage rejection
            create_task_history(
                task=task,
                approval_status='Rejected',
                task_status=task.task_status,
                created_by_user=request.user
            )
            
            response_message = f"Stage '{stage.stage_name}' has been rejected."
        
        # Return response
        serializer = TaskSerializer(task)
        return Response({
            'message': response_message,
            'task': serializer.data
        }, status=status.HTTP_200_OK)

class SimpleTokenObtainPairView(TokenObtainPairView):
    serializer_class = SimpleTokenObtainPairSerializer

    # def post(self, request, *args, **kwargs):
    #     serializer = self.serializer_class(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     tokens = serializer.validated_data

    #     response = Response(
    #         {"message": "Login successful"},
    #         status=status.HTTP_200_OK
    #     )

    #     # Store access token in cookie (can be JS-readable or HttpOnly)
    #     response.set_cookie(
    #         key='access_token',
    #         value=tokens['access'],
    #         httponly=False,  # set to True if you want HttpOnly
    #         secure=True,
    #         samesite='Lax',
    #         max_age=5 * 60  # 5 minutes
    #     )

    #     # Store refresh token in HttpOnly cookie (secure)
    #     response.set_cookie(
    #         key='refresh_token',
    #         value=tokens['refresh'],
    #         httponly=True,
    #         secure=True,
    #         samesite='Lax',
    #         max_age=7 * 24 * 60 * 60  # 7 days
    #     )

    #     return response
@method_decorator(csrf_exempt, name='dispatch')
class SignupAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = AdminUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(request.data.get('password1'))
            user.is_active = True
            user.save()
            return Response({
                'message': 'User created successfully',
                'user': AdminUserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
from rest_framework.generics import RetrieveAPIView
class TaskRetrieveAPIView(RetrieveAPIView):
    """
    GET /api/tasks/<task_id>/
    Returns a task with its category and stage details.
    """
    queryset = Task.objects.all()
    serializer_class = TaskDetailSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'