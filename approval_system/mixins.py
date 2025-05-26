from django.db import models
from . import settings

class TimestampMixin(models.Model):
    created_at = models.DateTimeField(auto_now_add=True,null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_created'
    )
    changed_at = models.DateTimeField(auto_now=True,null=True, blank=True)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_changed'
    )

    class Meta:
        abstract = True