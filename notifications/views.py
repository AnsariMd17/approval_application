from django.shortcuts import render

# Create your views here.
from approval_app.models import AdminUser
from notifications.models import *
from django.http import JsonResponse
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils import timezone
from rest_framework.pagination import PageNumberPagination
from collections import OrderedDict
from .serializers import *


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


class customfield_additionPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    custom_all_count = None

    def get_paginated_response(self, data, **kwargs):

        response_value = OrderedDict([
            ('total_items', self.page.paginator.count if not self.custom_all_count else self.custom_all_count),
            ('total_pages', self.page.paginator.num_pages),
            ('current_page', self.page.number),
            ('next', self.get_next_link() if not self.custom_all_count else None),
            ('previous', self.get_previous_link() if not self.custom_all_count else None),
            ('items_per_page', self.get_page_size(self.request)),
            ('results', data)  # Ensure you include the 'results' key with the paginated data
        ])

        # Update the response with any additional keyword arguments
        response_value.update(kwargs)
        return Response(response_value)


class UserNotificationsAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user_id = request.user.id
        page_source = request.GET.get('page_source', '')
        search_query = request.GET.get('search', None)
        archived = request.GET.get('archived', None)
        is_expired = request.GET.get('is_expired', None)
        
        try:
            user = AdminUser.objects.get(id=user_id)
           
        except AdminUser.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        # Base query for notifications
        notifications = Notification.objects.filter(recipient_id=user_id)
       

        # if is_expired is not None:
        #     ## expired notification will not be displayed in dashboard
        #     if is_expired.lower() == 'true':
        #         notifications = notifications.filter(is_expired=True)
               
        #     elif is_expired.lower() == 'false':
        #         notifications = notifications.filter(is_expired=False)
                
        #     else:
        #         return Response({"detail": "Invalid value for is_expired parameter. Use \'true\' or \'false\'."}, status=status.HTTP_400_BAD_REQUEST)

        # Apply archived filter if archived parameter is provided
        if archived is not None:
            if archived.lower() == 'true':
                notifications = notifications.filter(is_archive=True)

                if search_query:
                    notifications = notifications.filter(message__icontains=search_query)

                # Order by changed_by for archived notifications
                notifications = notifications.order_by('-changed_at')
               
            elif archived.lower() == 'false':
                # Handle non-archived notifications search
                notifications = notifications.filter(is_archive=False)
                
                if search_query:
                    notifications = notifications.filter(message__icontains=search_query)
                    
                notifications = notifications.order_by('-created_at')
                            
            else:
                return Response({"detail": "Invalid value for archived parameter. Use 'true' or 'false'."}, status=status.HTTP_400_BAD_REQUEST)
            
        elif page_source:
            new_source = [source.strip() for source in page_source.split(',')]
            notifications = notifications.filter(app_name__in=new_source)
           
            # Apply is_expired filter within the page_source logic
            if is_expired is not None:
                if is_expired.lower() == 'true':
                    notifications = notifications.filter(is_expired=True)
                    
                elif is_expired.lower() == 'false':
                    notifications = notifications.filter(is_expired=False)
                    
            notifications = notifications.order_by('-created_at')
                        
        else:
            # Default to non-archived notifications if no parameter is provided
            notifications = notifications.filter(is_archive=False)
           
            if search_query:
                notifications = notifications.filter(message__icontains=search_query)
                
            notifications = notifications.order_by('-created_at')
            
        if not notifications.exists():
            return Response({"detail": "No notifications found for this user."}, status=status.HTTP_200_OK)

        non_read_counts =  Notification.objects.filter(recipient_id=user_id,is_read=False).count()
        
        # Apply pagination using the same custom paginator
        paginator = customfield_additionPagination()
        paginated_notifications = paginator.paginate_queryset(notifications, request)
        serializer = NotificationSerializer(paginated_notifications, many=True, context={'request': request})

        result = paginator.get_paginated_response(serializer.data,non_read_counts=non_read_counts)
        return result

    def put(self, request):
        if request.method == 'PUT':
            user_id = request.user.id
            notification_ids = request.data.get('notification_ids', [])
            archive_action = request.data.get('is_archive', False)

            if isinstance(archive_action, str):
                archive_action = archive_action.lower() == 'true'

            if not isinstance(notification_ids, list):
                return Response({"detail": "Invalid payload format. 'ids' must be a list."}, status=status.HTTP_400_BAD_REQUEST)

            if not notification_ids:
                return Response({"detail": "No notification IDs provided."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                 # Determine if the action is to archive notifications
                if archive_action:
                    # Update the is_archived status for the provided list of notification IDs
                    count = Notification.objects.filter(id__in=notification_ids, recipient_id=user_id).update(is_archive=True, changed_at=timezone.now(), changed_by=user_id)

                    if count == 0:
                        return Response({"detail": "No notifications found for the provided IDs."}, status=status.HTTP_404_NOT_FOUND)

                    return Response({"detail": f"{count} notifications archived."}, status=status.HTTP_200_OK)
                else:
                    # Update the is_read status for the provided list of notification IDs
                    count = Notification.objects.filter(id__in=notification_ids, recipient_id=user_id).update(is_read=True, changed_by=user_id, changed_at=timezone.now())

                    if count == 0:
                        return Response({"detail": "No notifications found for the provided IDs."}, status=status.HTTP_404_NOT_FOUND)

                    return Response({"detail": f"{count} notifications marked as read."}, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)