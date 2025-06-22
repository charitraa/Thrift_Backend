from rest_framework.permissions import BasePermission
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

class LoginRequiredPermission(BasePermission):
    """
    Custom permission to return a specific message when the user is not authenticated.
    """

    def has_permission(self, request, view):
        token = request.COOKIES.get("access_token")
        if not token:
            raise AuthenticationFailed(detail="{message: Login first}", code=401)

        # Manually authenticate the user
        auth = JWTAuthentication()
        try:
            validated_token = auth.get_validated_token(token)
            request.user = auth.get_user(validated_token)  # Set the authenticated user
        except Exception:
            raise AuthenticationFailed(detail="{message: Invalid token}", code=401)

        return True


class IsSuperuserOrAdmin(BasePermission):
    """
    Custom permission to allow access only to superusers or staff.
    """
    def has_permission(self, request, view):
        # Only deny access if the user is neither a superuser nor staff
        if not (request.user.is_superuser or request.user.is_staff):
            raise AuthenticationFailed(detail="{message: You do not have permission to access}", code=401)
        return True