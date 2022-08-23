from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from example import views

urlpatterns = [


    # User Register
    path('register/', views.UserCreateView.as_view(), name="user-register"),

    # User Login
    path('login/', views.UserLoginView.as_view(), name="user-login"),

    # change password
    path('change_password/', views.ChangePasswordView.as_view(), name='auth_change_password'),


    # Token RefreshView
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Password reset email
    path('request-reset-email/', views.RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),

    # Password email uid token check
    path('password_reset/<uidb64>/<token>/',
         views.PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),

    # set new password
    path('password_reset_complete', views.SetNewPasswordView.as_view(),
         name='password-reset-complete'),

    # Create City Or Country
    path('city/', views.CityCreateView.as_view(), name='city-country-create'),
    
    # Update City Or Country
    path('city/<int:id>/', views.UpdateCityView.as_view(), name='city-country-update'),

    # Create Trip
    path('trip/', views.TripCreateView.as_view(), name='new-trip-create'),

    # User Register
    path('trip/<int:id>/', views.UpdateTripView.as_view(), name="trip-update"),
     


]
