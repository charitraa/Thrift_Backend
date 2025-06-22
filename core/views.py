from django.urls import reverse
from django.http import JsonResponse
from django.contrib.auth import authenticate, get_user_model
from django.core.mail import send_mail
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from pemissions.permission import LoginRequiredPermission
from .models import PasswordResetToken
from .serializers import UserCreateSerializer, UserSerializer


User = get_user_model()

class LoginView(TokenObtainPairView):
    """
    Custom login view that supports authentication via email or username.
    """

    def post(self, request, *args, **kwargs):
        identifier = request.data.get("username")  # could be username or email
        password = request.data.get("password")

        if not identifier or not password:
            return Response({"message": "Username / Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # If identifier looks like an email
            if "@" in identifier:
                user = User.objects.get(email__iexact=identifier)
            else:
                user = User.objects.get(username__iexact=identifier)

            # Now authenticate using email (your USERNAME_FIELD)
            user = authenticate(email=user.email, password=password)

            if user is not None:
                refresh = RefreshToken.for_user(user)
                user_serializer = UserSerializer(user)
                response =Response({
                    'message': 'Login successful',
                    'data': user_serializer.data,
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }, status=status.HTTP_200_OK)

                response.set_cookie(
                key="access_token",
                value=str(refresh.access_token),
                httponly=True,
                secure=True,  # Must be True in production
                samesite="None"  # Only use "None" when `secure=True`
            )
                return response

        except User.DoesNotExist:
            return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


class CreateUserView(APIView):
    """
    View for user registration.
    """
    def post(self, request, *args, **kwargs):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgetPassword(APIView):
    """
    View to send a password reset email to the user.
    """
    permission_classes = [LoginRequiredPermission]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        if not email:
            return Response({"message": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            
            # Generate reset token
            reset_token = PasswordResetToken.generate_token(user)
            
            # Construct reset URL
            reset_url = reverse("reset-password", args=[reset_token.token])

            # Send reset email
            send_mail(
                subject="Password Reset Request",
                message=f"Click the link below to reset your password:\n\nhttp://yourfrontend.com{reset_url}",
                from_email="no-reply@yourdomain.com",
                recipient_list=[email],
            )

            return Response({"message": "Password reset email sent successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"message": "User with given email does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
class UserLogoutView(APIView):
    """
    View to log out the user and blacklist the refresh token.
    """
    permission_classes = [LoginRequiredPermission]

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()  # Blacklist the refresh token
            except Exception:
                return Response({"message": "Invalid refresh token"}, status=status.HTTP_400_BAD_REQUEST)

        # Remove tokens from cookies
        response = Response({"message": "User logged out successfully"}, status=status.HTTP_200_OK)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        return response

def custom_server_error(request):
    return JsonResponse(
        {"message": "This is chari's fault. Talk to chari."},
        status=500
    )

