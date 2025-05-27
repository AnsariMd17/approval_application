from django.urls import path
from . import views
from .views import *


urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('admin-users/', views.AdminListDetailAPI.as_view(), name='admin_user_list'),
    path('admin-users/<int:admin_id>/', views.AdminListDetailAPI.as_view(), name='admin_user_list'),
    # path('clients/', views.client_list, name='client_list'),
    # path('add-admin-user/', views.add_admin_user, name='add_admin_user'),
    # path('edit-admin-user/<int:user_id>/', views.edit_admin_user, name='edit_admin_user'),
    # path('delete-admin-user/<int:user_id>/', views.delete_admin_user, name='delete_admin_user'),
    path('add-client/', views.AddClientAPI.as_view(), name='add_client'),
    path('edit-client/<int:client_id>/', views.EditClientAPI.as_view(), name='edit_client'),
    path('delete-client/<int:client_id>/', views.DeleteClientAPI.as_view(), name='delete_client'),
    path('login/', views.admin_login, name='admin_login'),
    path('signup/', views.admin_signup, name='admin_signup'),
    path('api/logout/', views.LogoutView.as_view(), name='logout'),
    path('api/clients/', views.ClientListDetailAPI.as_view(), name='client-list-api'),
    path('api/clients/<int:client_id>/', views.ClientListDetailAPI.as_view(), name='client-detail-api'),
    path('category/',views.CategoryListCreate.as_view(),name='approver-category'),
    path('category/<int:pk>/', CategoryRetrieveUpdateDestroy.as_view(), name='approver-category-detail'),
    path('tasks/', TaskListCreate.as_view(), name='task-list-create'),
    path('tasks/<int:pk>/', TaskRetrieveUpdateDestroy.as_view(), name='task-detail'),
]

