"""
URL configuration for Projekt project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.shortcuts import redirect
# from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
import Szyfrowanie.views

urlpatterns = [
    #    path('admin/', admin.site.urls),
    path("szyfruj/", Szyfrowanie.views.Szyfrowanie_Widok.as_view(), name="szyfruj"),
    path("deszyfruj/", Szyfrowanie.views.De_Szyfrowanie_Widok.as_view(), name="deszyfruj"),
    path('rejestracja/', Szyfrowanie.views.Rejestracja_Widok.as_view(), name='rejestracja'),
    path('logowanie/', Szyfrowanie.views.Logowanie_Widok.as_view(), name='logowanie'),
    path('wylogowanie/', Szyfrowanie.views.Wylogowanie_Widok.as_view(), name='wylogowanie'),
    path('odswiez/', TokenRefreshView.as_view(), name='odswiez_token'),
    path('moje_pliki/', Szyfrowanie.views.Moje_Pliki_Widok.as_view(), name='moje_pliki'),
    path('info/', Szyfrowanie.views.Info.as_view(), name='info'),
    path("moje_pliki/pobierz/<int:pk>/", Szyfrowanie.views.Pobierz_Plik.as_view(), name="pobierz_plik"),
    path("moje_pliki/usun/<int:pk>/", Szyfrowanie.views.Usun_Plik.as_view(), name="usun_plik"),
    path("moje_pliki/odszyfruj/<int:pk>/", Szyfrowanie.views.Odszyfruj_Plik.as_view(), name="odszyfruj_plik"),
]


handler404 = lambda request, exception=None: redirect('info')