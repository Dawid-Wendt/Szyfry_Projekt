from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from django.views import View
from django.shortcuts import render,redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from .forms import Form_Szyfr, Form_De_Szyfr, Form_Rejestracja, Form_Logowanie, Form_Dodaj_Plik
from .algorytmy import SZYFRY,DE_SZYFRY
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import HttpResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.files.base import ContentFile
from .models import Plik
import secrets
from datetime import datetime

# Widok do rejestracji
class Rejestracja_Widok(View):
    """Widok rejestracji użytkownika"""
    template_name = "rejestracja.html"

    def get(self, request):
        formularz = Form_Rejestracja()
        return render(request, self.template_name, {"formularz": formularz})

    def post(self, request):
        formularz = Form_Rejestracja(request.POST)
        if formularz.is_valid():
            try:
                user = User.objects.create_user(
                    username=formularz.cleaned_data["username"],
                    password=formularz.cleaned_data["haslo"]
                )
                login(request, user)
                messages.success(request, "Rejestracja udana.", extra_tags="fade")
                return redirect("moje_pliki")
            except Exception as e:
                messages.error(request, f"Błąd rejestracji: {str(e)}", extra_tags="fade")

        return render(request, self.template_name, {"formularz": formularz})

class Logowanie_Widok(View):
    """Widok logowania użytkownika """
    template_name = "logowanie.html"

    def get(self, request):
        formularz = Form_Logowanie()
        return render(request, self.template_name, {"formularz": formularz})

    def post(self, request):
        formularz = Form_Logowanie(data=request.POST)
        if formularz.is_valid():
            user = authenticate(
                request,
                username=formularz.cleaned_data["username"],
                password=formularz.cleaned_data["password"]
            )
            if user is not None:
                login(request, user)

                # Generowanie tokena JWT
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                messages.success(request, "Zalogowano pomyślnie.", extra_tags="fade")
                return redirect("moje_pliki")

        messages.error(request, "Nieprawidłowa nazwa użytkownika lub hasło.", extra_tags="fade")
        return render(request, self.template_name, {"formularz": formularz})

class Wylogowanie_Widok(View):
    def get(self, request):
        logout(request)
        messages.info(request, "Wylogowano pomyślnie.", extra_tags="fade")
        return redirect("logowanie")


class Szyfrowanie_Widok(FormView):
    template_name = "szyfrowanie.html"
    form_class = Form_Szyfr
    success_url = reverse_lazy("szyfrowanie")


    def post(self, request, *args, **kwargs):
        if "zapisz_do_bazy" in request.POST and request.user.is_authenticated:
            zaszyfrowany = request.POST.get("tekst")
            metoda = request.POST.get("metoda")
            klucz = request.POST.get("klucz")

            content = ContentFile(zaszyfrowany.encode("utf-8"))
            czas = datetime.now()
            file_name = f"plik_{metoda}_{czas.strftime("%Y-%m-%d_%H-%M-%S")}.txt"

            plik = Plik(szyfr=metoda, user_id=request.user, klucz=klucz, date_created=czas)
            plik.file.save(file_name, content)
            plik.save()

            return redirect("moje_pliki")

        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        tekst = form.cleaned_data["tekst"]
        metoda = form.cleaned_data["metoda"]
        klucz = form.cleaned_data["klucz"] or secrets.token_hex(16)
        czas = datetime.now()

        funkcja = SZYFRY.get(metoda)
        zaszyfrowany = funkcja(tekst, klucz) if funkcja else (None, None)

        if zaszyfrowany[0] is None:
            messages.error(self.request, "Szyfrowanie się nie powiodło.", extra_tags="fade")

        return self.render_to_response(self.get_context_data(
            form=form,
            zaszyfrowany_tekst=zaszyfrowany[0],
            metoda=metoda,
            klucz = zaszyfrowany[1],
            date_created=czas
        ))
class De_Szyfrowanie_Widok(FormView):
    template_name = "de_szyfrowanie.html"
    form_class = Form_De_Szyfr
    success_url = reverse_lazy("szyfrowanie")

    def form_valid(self, formularz):
        tekst = formularz.cleaned_data["tekst"]
        plik = formularz.cleaned_data["plik"]
        metoda = formularz.cleaned_data["metoda"]
        klucz = formularz.cleaned_data.get("klucz").strip()

        if plik:
            tekst = plik.read().decode("utf-8", errors="ignore").strip()

        funkcja_de_szyfrowania = DE_SZYFRY.get(metoda)
        deszyfrowany_tekst = funkcja_de_szyfrowania(tekst, klucz) if funkcja_de_szyfrowania else "Błąd: nieznana metoda szyfrowania"

        if deszyfrowany_tekst is None:
            messages.error(self.request, "Deszyfrowanie się nie powiodło. Sprawdź dane wejściowe.", extra_tags="fade")

        return self.render_to_response(self.get_context_data(form=formularz, deszyfrowany_tekst=deszyfrowany_tekst))

class Moje_Pliki_Widok(LoginRequiredMixin,FormView):
    template_name = "moje_pliki.html"
    login_url = "logowanie"

    def get(self, request):
        pliki = Plik.objects.filter(user_id=request.user)
        formularz = Form_Dodaj_Plik()
        return render(request, self.template_name, {"pliki": pliki, "formularz": formularz})

    def post(self, request):
        formularz = Form_Dodaj_Plik(request.POST, request.FILES)
        if formularz.is_valid():
            plik = formularz.cleaned_data["plik"]
            metoda = formularz.cleaned_data["metoda"]
            klucz = formularz.cleaned_data.get("klucz")
            tekst = plik.read().decode("utf-8", errors="ignore")
            plik.seek(0)
            deszyfruj = DE_SZYFRY.get(metoda)
            if deszyfruj:
                try:
                    wynik = deszyfruj(tekst, klucz)
                    if wynik is None:
                        messages.error(request, "Błąd deszyfrowania", extra_tags="fade")
                        return redirect("moje_pliki")
                except:
                    messages.error(request, "Błąd deszyfrowania", extra_tags="fade")
                    return redirect("moje_pliki")

            Plik.objects.create(
                file=plik,
                szyfr=metoda,
                user_id=request.user,
                date_created=datetime.now(),
                klucz=klucz
            )
        else:
            messages.error(request, "Niepoprawne dane formularza.", extra_tags="fade")
        return redirect("moje_pliki")

class Pobierz_Plik(View):
    def get(self, request, pk):
        plik = Plik.objects.get(id=pk, user_id=request.user)
        return HttpResponse(plik.file, content_type='text/plain', headers={
            'Content-Disposition': f'attachment; filename={plik.file.name}'
        })

class Usun_Plik(View):
    def post(self, request, pk):
        plik = Plik.objects.get(id=pk, user_id=request.user)
        plik.delete()
        return redirect("moje_pliki")

class Odszyfruj_Plik(View):
    def post(self, request, pk):
        plik = Plik.objects.get(id=pk, user_id=request.user)
        plik.file.seek(0)
        tekst = plik.file.read().decode("utf-8")
        funkcja = DE_SZYFRY.get(plik.szyfr)
        wynik = funkcja(tekst,plik.klucz) if funkcja else "Błąd odszyfrowywania"
        if wynik is None:
            messages.error(self.request, "Deszyfrowanie się nie powiodło. Sprawdź dane wejściowe.", extra_tags="fade")

        formularz = Form_Dodaj_Plik()

        pliki = Plik.objects.filter(user_id=request.user)
        return render(request, "moje_pliki.html", {"pliki": pliki, "odszyfrowany": wynik,"formularz": formularz})

class Info(View):
    """Widok prezentujący opis algorytmów szyfrowania """
    template_name = "szyfry_info.html"

    def get(self, request):
        return render(request, self.template_name)