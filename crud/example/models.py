from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser, PermissionsMixin
)
from django.core.validators import RegexValidator
from django.conf import settings

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, **kwargs):
        print(kwargs)

        if 'email' in kwargs and 'username' in kwargs:
            email = kwargs.pop("email")
            username = kwargs.pop("username")
            user = self.model(
                email=self.normalize_email(email), username=username, **kwargs
            )

        elif 'username' in kwargs:
            username = kwargs.pop("username")
            user = self.model(
                username=username, **kwargs
            )

        elif 'email' in kwargs:
            email = kwargs.pop("email")
            user = self.model(
                email=self.normalize_email(email),
                **kwargs

            )
        else:
            raise ValueError('Users must have an email')

        password = kwargs.get('password', None)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **kwargs):
        user = self.create_user(
            email=self.normalize_email(email),
            **kwargs,
        )
        user.set_password(password)
        user.is_staff = True
        user.admin = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


ALPHABET_NAME = '^[a-zA-Z ]+$'


class User(AbstractBaseUser, PermissionsMixin):
    """create all authenticated users"""
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True
    )
    username = models.CharField(max_length=30, validators=[RegexValidator(
        regex=ALPHABET_NAME,
        message='Not allowed special characters in name',
        code='invalid_name'
    )])
    name = models.CharField(max_length=50)
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'

    def __str__(self):
        return str(self.email)

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True




class TimeAt(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class CityCountry(models.Model):
    city = models.CharField(max_length=90)
    country = models.CharField(max_length=90)


    def __str__(self):
        return '{} - {}'.format(self.city, self.country)


class Trip(TimeAt):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    from_city = models.ForeignKey(CityCountry, on_delete=models.CASCADE, related_name='from_city', null=True)
    to_city = models.ForeignKey(CityCountry, on_delete=models.CASCADE, related_name='to_city', null=True)
    date = models.DateField()
    distance = models.IntegerField()
    days = models.IntegerField()

    def __str__(self):
        return str(self.user)


class Place(models.Model):
    name = models.CharField(max_length=90)
    image = models.URLField(max_length=10000, null=True, blank=True)
    line = models.TextField(max_length=200, null=True, blank=True)
    trip = models.ForeignKey(Trip, on_delete=models.CASCADE)
    addres = models.CharField(max_length=2000, null=True)

    def __str__(self):
        return str(self.name)
