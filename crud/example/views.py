import jwt
from django.conf import settings
from django.contrib.auth.models import update_last_login
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (Authenticate, ChangePasswordSerializer, CityCountrySerializer, GetCityCountrySerializer, TripCreateSerializer, TripSerializer, UpdateCityCountrySerializer, UpdateTripSerializer, UserLoginSerializer,
                          ResetPasswordEmailRequestSerializer,
                          SetNewPasswordSerializer, UserCreateSerializer)
from django.urls import reverse

from example.models import User, CityCountry, Trip

class UserCreateView(generics.CreateAPIView):
    """This view endpoint for Branch Manager create"""
    serializer_class = UserCreateSerializer
    permission_classes = (AllowAny,)
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, ]

    def get_queryset(self):
        return User.objects.all()

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        
        return Response(user_data, status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
    """This view endpoint for Ownerlogin"""
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            print(serializer.data)
            email = serializer.data['email']
            user = User.objects.get(email=email)
            if user.check_password(serializer.data['password']) is False:
                error = {'password': ["Password is wrong", ]}
                return Response(error, status=status.HTTP_400_BAD_REQUEST)
            elif not user.is_active:
                error = {'email': ["This user account is disabled.", ]}
                return Response(error, status=status.HTTP_400_BAD_REQUEST)
            elif not user.is_verified:
                error = {'email': ["This user account Email Address not verified.", ]}
                return Response(error, status=status.HTTP_400_BAD_REQUEST)
            else:
                update_last_login(None, user)
                data = Authenticate(user, context={"request": self.request}).data
                return Response(data, status=status.HTTP_200_OK)
        except User.DoesNotExist as e:
            error = {'email': ["This email/username is not valid", ]}
            return Response(error, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(generics.UpdateAPIView):
    """This view endpoint for Owner change password"""
    serializer_class = ChangePasswordSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user


class RequestPasswordResetEmail(generics.GenericAPIView):
    """If user can request reset password then after his receive reset
        Password mail link"""
    serializer_class = ResetPasswordEmailRequestSerializer

    def get_queryset(self):
        return User.objects.all()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email', '')
        serializer.is_valid(raise_exception=True)
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    """Reset password token verify check api"""
    serializer_class = SetNewPasswordSerializer

    def get_queryset(self):
        return User.objects.all()

    def get(self, request, uidb64, token, redirect_url=None):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid,please Request a new one'})

            return Response({'success': True, 'message': 'Credetials Valid', 'uidb64': uidb64, 'token': token})

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid,please Request a new one'})


class SetNewPasswordView(generics.GenericAPIView):
    """after token verfiy owner can set new password """
    serializer_class = SetNewPasswordSerializer

    def get_queryset(self):
        return User.objects.all()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)

class CityCreateView(generics.ListCreateAPIView):
    """This endpoint view for create New trip
       or get trip details"""
    serializer_class = CityCountrySerializer
    permission_classes = (AllowAny,)

    def get_queryset(self):
        return CityCountry.objects.all().order_by("-id")

    def get_serializer_class(self):
        if self.request.method == "GET":
            return GetCityCountrySerializer
        else:
            return CityCountrySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({'message': 'New City Or Country Created Successfully!'}, status=status.HTTP_201_CREATED)


class UpdateCityView(generics.RetrieveUpdateDestroyAPIView):
    """This view endpoint for Clinic Addtional Information Update"""
    serializer_class = UpdateTripSerializer
    permission_classes = (AllowAny, )
    lookup_field = "id"

    def get_queryset(self):
        return CityCountry.objects.filter(id=self.kwargs.get("id"))

    def get_serializer_class(self):
        if self.request.method == "GET":
            return GetCityCountrySerializer
        else:
            return UpdateCityCountrySerializer


class TripCreateView(generics.ListCreateAPIView):
    """This endpoint view for create New trip
       or get trip details"""
    serializer_class = TripCreateSerializer
    permission_classes = (IsAuthenticated, )

    def get_queryset(self):
        return Trip.objects.select_related('user', 'from_city', 'to_city').filter(user=self.request.user).prefetch_related('place_set').order_by("-id")

    def perform_create(self, serializer):
        return serializer.save(user=self.request.user)

    def get_serializer_class(self):
        if self.request.method == "GET":
            return TripSerializer
        else:
            return TripCreateSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({'message': 'Trip Created Successfully !'}, status=status.HTTP_201_CREATED)


class UpdateTripView(generics.RetrieveUpdateDestroyAPIView):
    """This view endpoint for Clinic Addtional Information Update"""
    serializer_class = UpdateTripSerializer
    permission_classes = (IsAuthenticated, )
    lookup_field = "id"

    def get_queryset(self):
        return Trip.objects.filter(id=self.kwargs.get("id")).select_related('user', 'from_city', 'to_city').filter(
            user=self.request.user).prefetch_related('place_set')

    def get_serializer_class(self):
        if self.request.method == "GET":
            return TripSerializer
        else:
            return UpdateTripSerializer