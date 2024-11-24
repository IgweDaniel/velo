from django.contrib.auth.models import AbstractUser
from django.db import models
from enum import Enum
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import random
import string


class OTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_requested_at = models.DateTimeField(null=True, blank=True)

    def is_valid(self):
        return timezone.now() < self.expires_at

    @staticmethod
    def generate_otp():
        return "".join(random.choices(string.digits, k=6))

    def __str__(self):
        return f"({self.otp}) {self.email} "


class UserType(Enum):
    DRIVER = "driver"
    RIDER = "rider"

    @classmethod
    def choices(cls):
        return [(key.value, key.name) for key in cls]


class User(AbstractUser):
    user_type = models.CharField(
        max_length=10, choices=UserType.choices(), default=UserType.RIDER.value
    )
    email = models.EmailField(unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "password"]

    def __str__(self):
        return f"{self.email} "


class Driver(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    name = models.CharField(max_length=100)
    vehicle_type = models.CharField(max_length=50)
    location = models.CharField(max_length=100)  # Store cell ID from S2
    available = models.BooleanField(default=True)
    seats = models.IntegerField(default=4)

    def __str__(self):
        return self.name


class Rider(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    name = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    contact_number = models.CharField(max_length=15)

    def __str__(self):
        return self.user.email


class TripStatus(Enum):
    ONGOING = "ongoing"
    COMPLETED = "completed"

    @classmethod
    def choices(cls):
        return [(key.value, key.name) for key in cls]


class Trip(models.Model):
    driver = models.ForeignKey(Driver, on_delete=models.CASCADE)
    rider = models.ForeignKey(Rider, on_delete=models.CASCADE)
    start_location = models.CharField(max_length=100)  # S2 cell ID for the start
    end_location = models.CharField(max_length=100)  # S2 cell ID for the destination
    requested_at = models.DateTimeField(auto_now_add=True)
    trip_start_time = models.DateTimeField(auto_now_add=True)
    trip_end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20, choices=[("ongoing", "Ongoing"), ("completed", "Completed")]
    )

    def __str__(self):
        return f"Trip from {self.start_location} to {self.end_location}"
