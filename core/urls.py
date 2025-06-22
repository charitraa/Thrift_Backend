from django.urls import path
from .views import LoginView, CreateUserView, GetUserDataView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),  # Endpoint for user login
    path('create/', CreateUserView.as_view(), name='create_user'),  # Endpoint for user registration
    path('me/', GetUserDataView.as_view(), name='me'),  # Endpoint to fetch logged-in user data
]