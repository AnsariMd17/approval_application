from django import forms
from .models import AdminUser, Client

class AdminUserForm(forms.ModelForm):
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        required=True,  # Required for signup; can be set to False for edit forms if needed
        help_text='Enter a password.'
    )
    password2 = forms.CharField(
        label='Password confirmation',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        required=True,
        help_text='Enter the same password as before, for verification.'
    )

    class Meta:
        model = AdminUser
        fields = [
            'first_name', 'last_name', 'email', 'username', 'email_notification',
            'phone_number','is_approver', 'is_super_user'
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            'email_notification': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_approver': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_super_user': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
        if password1 or password2:
            if password1 != password2:
                self.add_error('password2', "Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data.get("password1")
        if password:
            user.set_password(password)
        if commit:
            user.save()
        return user

class ClientForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = [
            'first_name', 'middle_name', 'last_name', 
            'mobile_number', 'program', 'date_of_birth',
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'middle_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'mobile_number': forms.TextInput(attrs={'class': 'form-control'}),
            'program': forms.TextInput(attrs={'class': 'form-control'}),
            'date_of_birth': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
        }

