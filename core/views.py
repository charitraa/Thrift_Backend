from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from pemissions.permission import LoginRequiredPermission
from .models import PasswordResetToken
from .serializers import UserCreateSerializer, UserSerializer, UserUpdateSerializer
from django.core.mail import send_mail
from .models import PasswordResetToken
from django.urls import reverse


class LoginView(TokenObtainPairView):
    """
    View for user login to obtain access and refresh tokens.
    """
    
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        # Authenticate user
        user = authenticate(email=email, password=password)
        user_serializer = UserSerializer(user)

        if user is not None:
            # Generate access and refresh tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            response = Response({
                'message': 'Login successful',
                'data': user_serializer.data,
                'access': str(access_token),
                'refresh': str(refresh),
            }, status=status.HTTP_200_OK)

            # Set access token in cookies
            response.set_cookie(
                key="access_token",
                value=str(access_token),
                httponly=True,
                secure=True,  # Must be True in production
                samesite="None"  # Only use "None" when `secure=True`
            )

            return response

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


User = get_user_model()


class GetUserDataView(APIView):
    """
    View to retrieve the logged-in user's data.
    """
    permission_classes = [LoginRequiredPermission]

    def get(self, request, *args, **kwargs):
        token = request.COOKIES.get('access_token')

        auth = JWTAuthentication()
        validated_token = auth.get_validated_token(token)
        user = auth.get_user(validated_token)

        if not user:
            return Response({"message": "Invalid token"}, status=401)

        try:
            user_data = UserSerializer(user)
            return Response({
                'data': user_data.data,
                "message": "User data retrieved successfully"
            }, status=200)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=404)


class UpdateUserView(APIView):
    """
    View to update user details.
    """
    permission_classes = [LoginRequiredPermission]

    def put(self, request, *args, **kwargs):
        token = request.COOKIES.get('access_token')

        if not token:
            return Response({"message": "Access token missing"}, status=status.HTTP_401_UNAUTHORIZED)

        auth = JWTAuthentication()
        try:
            validated_token = auth.get_validated_token(token)
            user = auth.get_user(validated_token)
        except Exception:
            return Response({"message": "Invalid or expired token"}, status=status.HTTP_401_UNAUTHORIZED)

        # Allow partial updates
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)

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