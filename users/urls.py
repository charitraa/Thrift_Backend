from django.urls import path
from .views import GetUserDataView, UpdateUserView

urlpatterns = [
    path('update/', UpdateUserView.as_view(), name='update'),  # Endpoint for user login
    path('me/', GetUserDataView.as_view(), name='me'),  # Endpoint to fetch logged-in user data
]