from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.db import models

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