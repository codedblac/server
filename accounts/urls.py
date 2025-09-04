from django.urls import path
from .views import (
    RegisterView,
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    ProfileView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    AddressListCreateView,
    AddressRetrieveUpdateDeleteView,
)

urlpatterns = [
    # Authentication
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", CustomTokenObtainPairView.as_view(), name="login"),
    path("token/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),

    # User profile
    path("profile/", ProfileView.as_view(), name="profile"),

    # Password reset
    path("password-reset/", PasswordResetRequestView.as_view(), name="password_reset"),
    path("password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),

    # Addresses
    path("addresses/", AddressListCreateView.as_view(), name="addresses_list_create"),
    path("addresses/<int:pk>/", AddressRetrieveUpdateDeleteView.as_view(), name="address_detail"),
]
