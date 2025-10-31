# accounts/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('csrf/', views.get_csrf_token, name='csrf_token'),  # Para Angular
    path('register/', views.register_user, name='register'),
    path('register/2fa/verificar/', views.verificar_registro_2fa, name='verificar_2fa'),
    path('login/', views.login_user, name='login'),
    path('login/2fa/verificar/', views.verificar_login_2fa, name='verificar_login_2fa'),
    path('login/google/', views.google_login, name='google_login'),
    path('recuperar/', views.recuperar_contrasena, name='recuperar_contrasena'),
    path('restablecer/', views.restablecer_contrasena, name='restablecer_contrasena'),
]