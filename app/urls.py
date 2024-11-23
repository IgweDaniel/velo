from django.urls import include, path

from .views import (
    GenerateOTPView,
    DriverSignupView,
    PasswordUpdateView,
    RiderSignupView,
    UserProfileView,
    VerifyOTPView,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path("auth/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/verify-otp/", VerifyOTPView.as_view(), name="verify_otp"),
    path("auth/generate-otp/", GenerateOTPView.as_view(), name="generate_otp"),
    path("user/me/", UserProfileView.as_view(), name="user_profile"),
    path("user/driver/", DriverSignupView.as_view(), name="driver_signup"),
    path("user/rider/", RiderSignupView.as_view(), name="rider_signup"),
    path("user/password/", PasswordUpdateView.as_view(), name="password_update"),
]
