from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.db import models
from sendgrid.helpers.mail import Mail
from sendgrid import SendGridAPIClient
import json
from django.conf import settings

class PhoneNumberField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 15
        self.field_name = kwargs.pop('verbose_name', None)
        kwargs['validators'] = [RegexValidator(r'^\+?1?\d{9,15}$', f'Invalid {self.field_name} format.\nPlease Enter a valid Number format ')]
        super().__init__(*args, **kwargs)

    def get_prep_value(self, value):
        if value and not any(validator(value) is None for validator in self.validators):
            raise ValidationError(f'Invalid {self.field_name} format.\nPlease Enter a valid Number format ')
        return super().get_prep_value(value)
    

# def send_mail(to_email, subject, content):
#     sg = SendGridAPIClient(api_key=settings.SEND_GRID_API_KEY)
#     from_email = settings.SENDGRID_DEFAULT_FROM_EMAIL

#     message = Mail(
#         from_email=from_email,
#         to_emails=to_email,
#         subject=subject,
#         html_content=content
#     )

#     try:
#         response = sg.send(message)
#         print(f"Email has been sent successfully! Response: {response.status_code}")
#     except Exception as e:
#         err = json.loads(e.body.decode("utf-8"))
#         return False, err
#     return True, {}