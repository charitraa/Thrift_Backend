from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from django.contrib.auth import  get_user_model
from pemissions.permission import LoginRequiredPermission
from users.serializers import UserUpdateSerializer
from core.serializers import UserSerializer

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
    