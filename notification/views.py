from django.shortcuts import render

# Create your views here.
from approval_app.models import AdminUser
from notification.models import *
from django.http import JsonResponse
from rest_framework import status


def create_notification(message, redirect_url, recipient_id, created_by=None):
    """
    Create a notification with the given message, redirect URL, and recipient ID.
    
    Args:
        message (str): The message to be stored in the notification.
        redirect_url (str): The URL to which the notification will redirect.
        recipient_id (int): The ID of the user who will receive the notification.
    
    Returns:
        Notification: The created Notification object.
    """
    try:
        recipient = AdminUser.objects.get(id=recipient_id)
    except AdminUser.DoesNotExist:
        return JsonResponse({'error': f'No user found with id {recipient_id}'}, status=status.HTTP_400_BAD_REQUEST)

    notification = Notification(
        message=message,
        redirect_url=redirect_url,
        recipient=recipient,
        created_by=created_by
    )
    notification.save()
    return JsonResponse({'success': 'Notification created successfully'}, status=status.HTTP_201_CREATED)
