from django.shortcuts import render
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import Driver, Rider, User
from .serializers import (
    DriverSerializer,
    RiderSerializer,
    UserCreationSerializer,
    UserSerializer,
)
from rest_framework_simplejwt.tokens import RefreshToken

from django.utils import timezone
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import OTP
from .serializers import (
    OTPSerializer,
    OTPVerificationSerializer,
    UserCreationSerializer,
)

from .serializers import DriverSignupSerializer, RiderSignupSerializer


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


class DriverDetailView(generics.RetrieveAPIView):
    queryset = Driver.objects.all()
    serializer_class = DriverSerializer
    permission_classes = [IsAuthenticated]


class RiderDetailView(generics.RetrieveAPIView):
    queryset = Rider.objects.all()
    serializer_class = RiderSerializer
    permission_classes = [IsAuthenticated]


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


class RiderSignupView(generics.CreateAPIView):
    serializer_class = RiderSignupSerializer
    queryset = User.objects.all()
    permission_classes = []


class UserCreationView(generics.CreateAPIView):
    serializer_class = UserCreationSerializer
    queryset = User.objects.all()
    permission_classes = []


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


class UserList(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = []

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        user = User.objects.get(username=request.data["username"])
        user.set_password(request.data["password"])
        user.save()
        if request.data.get("userType") == "driver":
            Driver.objects.create(user=user)
        elif request.data.get("userType") == "rider":
            Rider.objects.create(user=user)
        return response
