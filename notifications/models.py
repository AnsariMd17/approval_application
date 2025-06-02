from django.db import models

# Create your models here.
from django.db import models
from approval_system.mixins import TimestampMixin
from django.conf import settings
# Create your models here.

class Notification(TimestampMixin):
    message = models.TextField()
    redirect_url = models.URLField(null=True, blank=True)
    is_read = models.BooleanField(default=False)
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,null=True, blank=True)
    is_archive = models.BooleanField(default=False)
    is_expired = models.BooleanField(default=False)
    
    def __str__(self):
        return self.message
    
    class Meta:
        db_table = 'Notification'


class MailTemplate(models.Model):
    
    name = models.CharField(max_length=255, unique=True)
    subject = models.CharField(max_length=255)
    html_content = models.TextField()
    
    
    def __str__(self):
        return self.name

    class Meta:
        db_table = 'mail_template' 