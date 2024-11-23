from rest_framework import serializers
from .models import Driver, Rider, User, UserType

from rest_framework import serializers

from .models import OTP


# serializers.py
from rest_framework import serializers
from .models import User, OTP, UserType, Driver, Rider


class BaseSignupSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(max_length=6, write_only=True)

    class Meta:
        model = User
        fields = ["username", "email", "password", "otp"]
        extra_kwargs = {"password": {"write_only": True}}

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

        user = User.objects.create_user(user_type=user_type, **validated_data)

        # Delete the OTP record after successful user creation
        OTP.objects.filter(email=email, otp=otp_value).delete()
        return user


# serializers.py
class DriverSignupSerializer(BaseSignupSerializer):
    name = serializers.CharField(max_length=100)
    vehicle_type = serializers.CharField(max_length=50)

    class Meta(BaseSignupSerializer.Meta):
        fields = BaseSignupSerializer.Meta.fields + ["name", "vehicle_type"]

    def create(self, validated_data):
        user = self.create_user(validated_data, UserType.DRIVER.value)
        Driver.objects.create(
            user=user,
            name=validated_data["name"],
            vehicle_type=validated_data["vehicle_type"],
        )
        return user


class RiderSignupSerializer(BaseSignupSerializer):
    name = serializers.CharField(max_length=100)
    contact_number = serializers.CharField(max_length=15)

    class Meta(BaseSignupSerializer.Meta):
        fields = BaseSignupSerializer.Meta.fields + ["name", "contact_number"]

    def create(self, validated_data):
        user = self.create_user(validated_data, UserType.RIDER.value)
        Rider.objects.create(
            user=user,
            name=validated_data["name"],
            contact_number=validated_data["contact_number"],
        )
        return user


class RiderSignupSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(max_length=6, write_only=True)
    name = serializers.CharField(max_length=100)
    contact_number = serializers.CharField(max_length=15)

    class Meta:
        model = User
        fields = ["username", "email", "password", "otp", "name", "contact_number"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate_otp(self, value):
        email = self.initial_data.get("email")
        try:
            otp_record = OTP.objects.get(email=email, otp=value)
            if not otp_record.is_valid():
                raise serializers.ValidationError("OTP has expired.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")
        return value

    def create(self, validated_data):
        otp_value = validated_data.pop("otp")
        email = validated_data.get("email")
        name = validated_data.pop("name")
        contact_number = validated_data.pop("contact_number")

        user = User.objects.create_user(
            user_type=UserType.RIDER.value, **validated_data
        )
        Rider.objects.create(user=user, name=name, contact_number=contact_number)

        # Delete the OTP record after successful user creation
        OTP.objects.filter(email=email, otp=otp_value).delete()
        return user


class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver
        fields = "__all__"


class RiderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rider
        fields = "__all__"


class DriverProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver
        exclude = ["user"]


class RiderProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rider
        exclude = ["user"]


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


class UserCreationSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(max_length=6, write_only=True)

    class Meta:
        model = User
        fields = ["username", "email", "password", "user_type", "otp"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate_otp(self, value):
        email = self.initial_data.get("email")
        try:
            otp_record = OTP.objects.get(email=email, otp=value)
            if not otp_record.is_valid():
                raise serializers.ValidationError("OTP has expired.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")
        return value

    def create(self, validated_data):
        otp_value = validated_data.pop("otp")
        email = validated_data.get("email")
        user = User.objects.create_user(**validated_data)
        # Delete the OTP record after successful user creation
        OTP.objects.filter(email=email, otp=otp_value).delete()
        return user


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
