from rest_framework import serializers
from .models import Driver, Rider, User, UserType

from rest_framework import serializers

from .models import OTP
from django.contrib.auth.password_validation import validate_password

# serializers.py
from rest_framework import serializers
from .models import User, OTP, UserType, Driver, Rider


from rest_framework import serializers
from .models import User, OTP


class BaseSignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    otp = serializers.CharField(max_length=6, write_only=True)

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(
                "A user with this username already exists."
            )
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_otp(self, value):
        email = self.initial_data.get("email")
        try:
            otp_record = OTP.objects.get(email=email, otp=value)
            if not otp_record.is_valid():
                raise serializers.ValidationError("OTP has expired.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")
        return value

    def create_user(self, validated_data, user_type):
        otp_value = validated_data.pop("otp")
        email = validated_data.get("email")

        user = User.objects.create_user(
            username=validated_data["username"],
            email=email,
            password=validated_data["password"],
            user_type=user_type,
        )

        OTP.objects.filter(email=email, otp=otp_value).delete()
        return user


class DriverSignupSerializer(BaseSignupSerializer):
    name = serializers.CharField(max_length=100)
    vehicle_type = serializers.CharField(max_length=50)

    def create(self, validated_data):
        name = validated_data.pop("name")
        vehicle_type = validated_data.pop("vehicle_type")

        user = self.create_user(validated_data, UserType.DRIVER.value)
        Driver.objects.create(user=user, name=name, vehicle_type=vehicle_type)
        return user


class RiderSignupSerializer(BaseSignupSerializer):
    name = serializers.CharField(max_length=100)
    contact_number = serializers.CharField(max_length=15)

    def create(self, validated_data):
        name = validated_data.pop("name")
        contact_number = validated_data.pop("contact_number")

        user = self.create_user(validated_data, UserType.RIDER.value)
        Rider.objects.create(user=user, name=name, contact_number=contact_number)
        return user


class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver
        fields = "__all__"


class DriverProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver
        exclude = ["user"]


class DriverUpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver
        exclude = ["user", "location"]


class RiderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rider
        fields = "__all__"


class RiderProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rider
        exclude = ["user"]


class RiderUpdateProfileSerializer(RiderProfileSerializer): ...


class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate_otp(self, value):
        email = self.initial_data.get("email")
        try:
            otp_record = OTP.objects.get(email=email, otp=value)
            if not otp_record.is_valid():
                raise serializers.ValidationError("OTP has expired.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")
        return value


class UserSerializer(serializers.ModelSerializer):
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "username", "email", "user_type", "profile"]

    def get_profile(self, obj):
        if obj.user_type == UserType.DRIVER.value:
            try:
                driver = Driver.objects.get(user=obj)
                return DriverProfileSerializer(driver).data
            except Driver.DoesNotExist:
                return None
        elif obj.user_type == UserType.RIDER.value:
            try:
                rider = Rider.objects.get(user=obj)
                return RiderProfileSerializer(rider).data
            except Rider.DoesNotExist:
                return None
        return None


class PasswordUpdateSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value
