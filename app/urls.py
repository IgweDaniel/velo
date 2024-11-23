from django.urls import include, path

from .views import (
    AuthenticatedUserView,
    GenerateOTPView,
    DriverSignupView,
    RiderSignupView,
    VerifyOTPView,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    # path("", include("djoser.urls")),
    # path("", include("djoser.urls.jwt")),
    path("auth/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/verify-otp/", VerifyOTPView.as_view(), name="verify_otp"),
    path("auth/generate-otp/", GenerateOTPView.as_view(), name="generate_otp"),
    path("user/me/", AuthenticatedUserView.as_view(), name="authenticated_user"),
    # path("user/", UserCreationView.as_view(), name="create_user"),
    path("user/driver/", DriverSignupView.as_view(), name="driver_signup"),
    path("user/rider/", RiderSignupView.as_view(), name="rider_signup"),
    # path("create/", UserList.as_view(), name="create_user"),
]
