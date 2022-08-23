from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import password_validation
from django.contrib import auth
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from example.models import User, CityCountry, Trip, Place


class Authenticate(serializers.ModelSerializer):
    token = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'name', 'country', 'city',   'token', 'is_active', 'is_verified')

    def get_token(self, instance):
        token = RefreshToken.for_user(self.instance).access_token
        return '{}'.format(token)

class UserSerializer(serializers.ModelSerializer):
    """Users login after can see this credentials"""

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'name', 'country', 'city', 'is_active', 'is_verified')



class UserListSerializer(serializers.ModelSerializer):
    """Users login after can see this credentials"""
    token = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'name', 'country', 'city',   'token', 'is_active', 'is_verified')


    # Authenticate Serializer represent
    def to_representation(self, instance):
        data = Authenticate(instance, context={"request": self.context.get('request')}).data
        return data

class UserCreateSerializer(serializers.ModelSerializer):
    """This serializer for site users registration"""
    token = serializers.SerializerMethodField(read_only=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True,
                                     required=True, validators=[validate_password, ])

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'name', 'country', 'city',   'password', 'token', 'is_active', 'is_verified')
        extra_kwargs = {
            'password': {'write_only': True},

        }
        read_only_fields = ('is_active', 'is_verified')

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    def get_token(self, instance):
        token = RefreshToken.for_user(self.instance).access_token
        return '{}'.format(token)    


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            return value
        else:
            raise serializers.ValidationError("This email address is not exist!")


class ChangePasswordSerializer(serializers.Serializer):
    """This serializer for change password"""
    old_password = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password1 = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password2 = serializers.CharField(max_length=128, write_only=True, required=True)
    token = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = ('old_password', 'new_password1', 'new_password2', 'token')

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                _('Your old password was entered incorrectly. Please enter it again.')
            )
        return value

    def get_token(self, instance):
        token = RefreshToken.for_user(self.instance).access_token
        return '{}'.format(token)

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': _("The two password fields didn't match.")})
        password_validation.validate_password(data['new_password1'], self.context['request'].user)
        return data

    def update(self, instance, validated_data):
        password = self.validated_data['new_password1']

        instance.set_password(password)
        instance.save()
        return instance


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    """This serializer for reset password email link"""
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            return email
        else:
            raise serializers.ValidationError("This user email not registered with system!")


class SetNewPasswordSerializer(serializers.Serializer):
    """This serializer for set new password after his
       forgot link is valid"""
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)


class GetCityCountrySerializer(serializers.ModelSerializer):
    """City Country Get """


    class Meta:
        model = CityCountry
        fields = ('id', 'city', 'country')


class CityCountrySerializer(serializers.ModelSerializer):
    """City Country create"""

    class Meta:
        model = CityCountry
        fields = ('city', 'country')


class UpdateCityCountrySerializer(serializers.ModelSerializer):
    """City Country create"""

    class Meta:
        model = CityCountry
        fields = ('city', 'country')


class PlaceSerializer(serializers.ModelSerializer):

    class Meta:
        model = Place
        fields = ('name', 'image', 'line', 'addres')



class TripSerializer(serializers.ModelSerializer):
    """Get New Trip Created data"""
    from_city = CityCountrySerializer(read_only=True)
    to_city = CityCountrySerializer(read_only=True)
    place = PlaceSerializer(read_only=True, many=True, source="place_set")
    user = UserSerializer(read_only=True)

    class Meta:
        model = Trip
        fields = ('id', 'user', 'from_city', 'to_city', 'date', 'distance', 'days', 'place', 'created_at', 'updated_at')


class TripCreateSerializer(serializers.ModelSerializer):
    """ New Trip Create"""
    from_city = CityCountrySerializer(write_only=True, required=False)
    to_city = CityCountrySerializer(write_only=True, required=False)
    place = PlaceSerializer(write_only=True, required=False, many=True)

    class Meta:
        model = Trip
        fields = ('from_city', 'to_city', 'date', 'distance', 'days', 'place')
        read_only_fields = ('user',)

    def create(self, validated_data):
        print(validated_data)
        from_city = validated_data.pop('from_city')
        to_city = validated_data.pop('to_city')
        city_f = CityCountry.objects.create(**from_city)
        city_t = CityCountry.objects.create(**to_city)
        place = validated_data.pop('place')

        instance = Trip.objects.create(from_city=city_f, to_city=city_t, **validated_data)
        array = []
        for dic in place:
            array.append(Place(**dic, trip=instance))
        Place.objects.bulk_create(array)
        return instance


class UpdateTripSerializer(serializers.ModelSerializer):
    """ Update Trip Create"""
    from_city = CityCountrySerializer(write_only=True, required=False)
    to_city = CityCountrySerializer(write_only=True, required=False)
    place = PlaceSerializer(write_only=True, required=False, many=True)

    class Meta:
        model = Trip
        exclude = ('user',)

