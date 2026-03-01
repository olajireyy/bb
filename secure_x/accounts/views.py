from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .models import CustomUser


def signup_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        full_name = request.POST.get('full_name', '')
        email = request.POST.get('email', '')
        phone = request.POST.get('phone', '')
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        user_type = request.POST.get('user_type', 'student')

        # Validate passwords match
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'authentication/signup.html')

        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'An account with this email already exists.')
            return render(request, 'authentication/signup.html')

        # Validate password strength
        try:
            validate_password(password)
        except ValidationError as e:
            for error in e.messages:
                messages.error(request, error)
            return render(request, 'authentication/signup.html')

        # Create the user
        user = CustomUser.objects.create_user(
            email=email,
            password=password,
            full_name=full_name,
            phone=phone,
            user_type=user_type,
        )

        # Auto-login after signup
        login(request, user)
        return redirect('dashboard')

    return render(request, 'authentication/signup.html')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid email or password.')

    return render(request, 'authentication/login.html')


def logout_view(request):
    logout(request)
    return redirect('login')


def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')
        reset_url = None

        try:
            user = CustomUser.objects.get(email=email)
            # Generate reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Build reset link
            reset_url = request.build_absolute_uri(f'/accounts/reset-password/{uid}/{token}/')
        except CustomUser.DoesNotExist:
            pass  # Don't reveal if email exists or not

        return render(request, 'authentication/forgot-password.html', {
            'email_sent': True,
            'reset_url': reset_url,  # Show link on page (dev mode)
        })

    return render(request, 'authentication/forgot-password.html')


def reset_password_view(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    # Verify token is valid
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            password = request.POST.get('password', '')
            confirm_password = request.POST.get('confirm_password', '')

            if password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'authentication/reset-password.html', {'valid_link': True})

            # Validate password strength
            try:
                validate_password(password, user)
            except ValidationError as e:
                for error in e.messages:
                    messages.error(request, error)
                return render(request, 'authentication/reset-password.html', {'valid_link': True})

            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successful! You can now sign in.')
            return redirect('login')

        return render(request, 'authentication/reset-password.html', {'valid_link': True})
    else:
        return render(request, 'authentication/reset-password.html', {'valid_link': False})


