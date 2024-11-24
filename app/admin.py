from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from app.models import OTP, Driver, Rider, Trip, User

# Register your models here.
admin.site.register(User, UserAdmin)
admin.site.register(Rider)
admin.site.register(Trip)
admin.site.register(Driver)
admin.site.register(OTP)
