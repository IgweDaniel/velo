from django.shortcuts import render
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import Driver, Rider, User
from .serializers import (
    DriverProfileSerializer,
    DriverSerializer,
    DriverUpdateProfileSerializer,
    PasswordUpdateSerializer,
    RiderProfileSerializer,
    RiderSerializer,
    RiderUpdateProfileSerializer,
    UserSerializer,
    OTPSerializer,
    OTPVerificationSerializer,
    DriverSignupSerializer,
    RiderSignupSerializer,
)
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import update_session_auth_hash

from django.utils import timezone
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import OTP


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


def format_serializer_error(errors):
    custom_response_data = {"error": {}}
    for field, value in errors.items():
        if isinstance(value, list) and len(value) == 1:
            custom_response_data["error"][field] = value[0]
        else:
            custom_response_data["error"][field] = value
    return custom_response_data


class ProfileUpdateView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.user.user_type == "driver":
            return DriverUpdateProfileSerializer
        elif self.request.user.user_type == "rider":
            return RiderUpdateProfileSerializer

    def get_queryset(self):
        if self.request.user.user_type == "driver":
            return Driver.objects.filter(user=self.request.user)
        elif self.request.user.user_type == "rider":
            return Rider.objects.filter(user=self.request.user)

    def get_object(self):
        if self.request.user.user_type == "driver":
            return self.request.user.driver
        elif self.request.user.user_type == "rider":
            return self.request.user.rider


class DriverDetailView(generics.RetrieveAPIView):
    queryset = Driver.objects.all()
    serializer_class = DriverSerializer
    permission_classes = [IsAuthenticated]


class RiderDetailView(generics.RetrieveAPIView):
    queryset = Rider.objects.all()
    serializer_class = RiderSerializer
    permission_classes = [IsAuthenticated]


class DriverProfileUpdateView(generics.UpdateAPIView):
    queryset = Driver.objects.all()
    serializer_class = DriverSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user.driver


class RiderProfileUpdateView(generics.UpdateAPIView):
    queryset = Rider.objects.all()
    serializer_class = RiderSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user.rider


class GenerateOTPView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            cooldown_period = timezone.timedelta(minutes=5)  # Set cooldown period here
            now = timezone.now()

            try:
                otp_record = OTP.objects.get(email=email)
                if (
                    otp_record.last_requested_at
                    and now - otp_record.last_requested_at < cooldown_period
                ):
                    remaining_time = cooldown_period - (
                        now - otp_record.last_requested_at
                    )
                    next_request_time = otp_record.last_requested_at + cooldown_period
                    return Response(
                        {
                            "error": f"Please wait {remaining_time.seconds // 60} minutes before requesting a new OTP.",
                            "next_request_time": next_request_time.isoformat(),
                        },
                        status=status.HTTP_429_TOO_MANY_REQUESTS,
                    )
            except OTP.DoesNotExist:
                otp_record = OTP(email=email)

            otp_record.otp = OTP.generate_otp()
            otp_record.expires_at = now + timezone.timedelta(minutes=10)
            otp_record.last_requested_at = now
            otp_record.save()

            next_request_time = now + cooldown_period
            print(f"Your OTP code is {otp_record.otp} for email {email}")
            # Send OTP to user's email or phone number here
            return Response(
                {
                    "message": "OTP sent successfully",
                    "next_request_time": next_request_time.isoformat(),
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            format_serializer_error(serializer.errors),
            status=status.HTTP_400_BAD_REQUEST,
        )


class VerifyOTPView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            return Response(
                {"message": "OTP is valid and has not expired."},
                status=status.HTTP_200_OK,
            )
        return Response(
            format_serializer_error(serializer.errors),
            status=status.HTTP_400_BAD_REQUEST,
        )


class DriverSignupView(generics.CreateAPIView):
    serializer_class = DriverSignupSerializer
    queryset = User.objects.all()
    permission_classes = []

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        response_serializer = UserSerializer(user)
        return Response(
            {"tokens": get_tokens_for_user(user), "user": response_serializer.data},
            status=status.HTTP_201_CREATED,
        )


class RiderSignupView(generics.CreateAPIView):
    serializer_class = RiderSignupSerializer
    queryset = User.objects.all()
    permission_classes = []

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        response_serializer = UserSerializer(user)
        return Response(
            {"tokens": get_tokens_for_user(user), "user": response_serializer.data},
            status=status.HTTP_201_CREATED,
        )


class PasswordUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = PasswordUpdateSerializer(
            data=request.data,
        )
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response(
                {"error": "Old password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(serializer.validated_data["new_password"])
        user.save()
        update_session_auth_hash(request, user)  # Important to keep the user logged in
        return Response(
            {"message": "Password updated successfully."}, status=status.HTTP_200_OK
        )


class AuthenticatedUserView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            serializer = self.get_serializer(user)
            return Response(serializer.data)
        else:
            return Response({"error": "User is not authenticated"}, status=401)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        view = AuthenticatedUserView.as_view()
        return view(request._request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        view = ProfileUpdateView.as_view()
        return view(request._request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        view = ProfileUpdateView.as_view()
        return view(request._request, *args, **kwargs)
