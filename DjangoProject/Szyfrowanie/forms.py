from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from .algorytmy import SZYFRY

class Form_Szyfr(forms.Form):
    tekst = forms.CharField(widget=forms.Textarea, label="Tekst do zaszyfrowania", max_length=1000,required=True)
    metoda = forms.ChoiceField(choices=[(klucz, klucz) for klucz in SZYFRY], label="Wybierz metodę szyfrowania")
    klucz = forms.CharField(label="Hasło (na podstawie którego powstanie klucz)", required=False)

class Form_De_Szyfr(forms.Form):
    tekst = forms.CharField(widget=forms.Textarea, label="Tekst do deszyfrowania", required=False)
    plik = forms.FileField(label="Plik z zaszyfrowanym tekstem", required=False)
    metoda = forms.ChoiceField(choices=[(klucz, klucz) for klucz in SZYFRY], label="Wybierz metodę szyfrowania")
    klucz = forms.CharField(widget=forms.Textarea, label="Klucz do deszyfrowania", required=True)

class Form_Rejestracja(forms.Form):
    username = forms.CharField(label="Nazwa użytkownika",error_messages={"required": "Musisz podać nazwę użytkownika."})
    haslo = forms.CharField(widget=forms.PasswordInput, label="Haslo", error_messages={"required": "Musisz podać hasło."})
    haslo2 = forms.CharField(widget=forms.PasswordInput, label="Powtórz hasło", error_messages={"required": "Musisz powtórzyć hasło."})

    def clean_username(self):
        username = self.cleaned_data["username"]
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Taki użytkownik już istnieje.")
        return username

    def clean(self):
        dane = super().clean()
        if dane.get("haslo") != dane.get("haslo2"):
            self.add_error("haslo", "Hasła się nie zgadzają.")
            self.add_error("haslo2", "Hasła się nie zgadzają!")
        return dane

class Form_Logowanie(forms.Form):
    username = forms.CharField(label="Nazwa użytkownika", error_messages={"required": "Wprowadź nazwę użytkownika."})
    password = forms.CharField(label="Hasło",widget=forms.PasswordInput, error_messages={"required": "Wprowadź hasło."})

class Form_Dodaj_Plik(forms.Form):
    plik = forms.FileField(label="Plik do dodania")
    metoda = forms.ChoiceField(choices=[(k, k) for k in SZYFRY], label="Metoda szyfrowania")
    klucz = forms.CharField(widget=forms.Textarea, label="Klucz do deszyfrowania", required=True)