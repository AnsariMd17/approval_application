from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from .models import AdminUser, Client
from .forms import AdminUserForm, ClientForm
from django.db.models import Q 
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import ClientSerializer, AdminUserSerializer


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


from .models import AdminUser

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


class AddClientAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ClientSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from django.contrib.auth import authenticate, login, logout
from rest_framework_simplejwt.tokens import RefreshToken
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

class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)
        except KeyError:
            return Response({"detail": "Refresh token not provided."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"detail": "Token is invalid or expired."}, status=status.HTTP_400_BAD_REQUEST)
        

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




# @login_required
# def admin_user_list(request):
#     admin_users = AdminUser.objects.order_by('-created_at')
#     search = request.GET.get('search')
#     if search:
#         admin_users = admin_users.filter(
#             Q(first_name__icontains=search) |
#             Q(last_name__icontains=search) |
#             Q(email__icontains=search) |
#             Q(username__icontains=search)
#         )
#     paginator = Paginator(admin_users, 10)
#     page_number = request.GET.get('page')
#     page_obj = paginator.get_page(page_number)
#     return render(request, 'approval_app/admin_user_list.html', {
#         'page_obj': page_obj,
#         'search': search
#     })



# @login_required
# def client_list(request):
#     clients = Client.objects.order_by('-created_at')
#     search = request.GET.get('search')
#     if search:
#         clients = clients.filter(
#             Q(first_name__icontains=search) |
#             Q(last_name__icontains=search) |
#             Q(program__icontains=search) |
#             Q(mobile_number__icontains=search)
#         )
#     program_filter = request.GET.get('program')
#     if program_filter:
#         clients = clients.filter(program__icontains=program_filter)
#     paginator = Paginator(clients, 10)
#     page_number = request.GET.get('page')
#     page_obj = paginator.get_page(page_number)
#     programs = Client.objects.values_list('program', flat=True).distinct().order_by('program')
#     return render(request, 'approval_app/client_list.html', {
#         'page_obj': page_obj,
#         'search': search,
#         'programs': programs,
#         'program_filter': program_filter
#     })

# @login_required
# def add_admin_user(request):
#     """Add new admin user"""
#     if request.method == 'POST':
#         form = AdminUserForm(request.POST)
#         if form.is_valid():
#             form.save()
#             messages.success(request, 'Admin user added successfully!')
#             return redirect('admin_user_list')
#     else:
#         form = AdminUserForm()
    
#     return render(request, 'approval_app/add_admin_user.html', {'form': form})


# @login_required
# def edit_admin_user(request, user_id):
#     """Edit admin user"""
#     user = get_object_or_404(AdminUser, id=user_id)
    
#     if request.method == 'POST':
#         form = AdminUserForm(request.POST, instance=user)
#         if form.is_valid():
#             form.save()
#             messages.success(request, 'Admin user updated successfully!')
#             return redirect('admin_user_list')
#     else:
#         form = AdminUserForm(instance=user)
    
#     return render(request, 'approval_app/edit_admin_user.html', {'form': form, 'user': user})


# @login_required
# def delete_admin_user(request, user_id):
#     """Delete admin user"""
#     user = get_object_or_404(AdminUser, id=user_id)
#     if request.method == 'POST':
#         user.delete()
#         messages.success(request, 'Admin user deleted successfully!')
#         return redirect('admin_user_list')
#     return render(request, 'approval_app/confirm_delete.html', {
#         'object': user,
#         'object_type': 'Admin User',
#         'cancel_url': 'admin_user_list'
#     })
