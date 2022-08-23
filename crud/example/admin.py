from django.contrib import admin
from example.models import User, CityCountry, Trip, Place

# Register your models here.
admin.site.register(User)
admin.site.register(CityCountry)
admin.site.register(Trip)
admin.site.register(Place)