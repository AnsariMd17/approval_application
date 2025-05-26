from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import AdminUser, Client


@admin.register(AdminUser)
class AdminUserAdmin(UserAdmin):
    list_display = (
        'username', 'first_name', 'last_name', 'email', 
        'is_approver', 'is_super_user', 'email_notification',
        'created_at', 'changed_at', 'created_by', 'changed_by'
    )
    list_filter = (
        'is_approver', 'is_super_user', 'email_notification', 
        'is_staff', 'is_active', 'created_at'
    )
    search_fields = ('username', 'first_name', 'last_name', 'email')

    readonly_fields = ('created_at', 'changed_at', 'created_by', 'changed_by')

    fieldsets = UserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': (
                 'phone_number', 'email_notification', 
                'is_approver', 'is_super_user',
                'created_at', 'changed_at', 'created_by', 'changed_by'
            )
        }),
    )

    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Additional Info', {
            'fields': (
                'first_name', 'last_name', 'email', 'phone_number',
                'email_notification', 'is_approver', 'is_super_user'
            )
        }),
    )

    # def save_model(self, request, obj, form, change):
    #     if not obj.pk:
    #         obj.created_by = request.user
    #     obj.changed_by = request.user
    #     super().save_model(request, obj, form, change)


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = (
        'first_name', 'last_name', 'mobile_number', 
        'program', 'created_at', 'changed_at', 'created_by', 'changed_by'
    )
    list_filter = ('program', 'created_at')
    search_fields = ('first_name', 'last_name', 'mobile_number')
    readonly_fields = ('created_at', 'changed_at', 'created_by', 'changed_by')

    # def save_model(self, request, obj, form, change):
    #     if not obj.pk:
    #         obj.created_by = request.user
    #     obj.changed_by = request.user
    #     super().save_model(request, obj, form, change)
