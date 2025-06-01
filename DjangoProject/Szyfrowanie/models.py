import datetime
from django.db import models
from django.conf import settings
from datetime import datetime

# Create your models here.
class Plik(models.Model):
    id = models.AutoField(primary_key=True)
    file = models.FileField(upload_to="files")
    szyfr = models.CharField(max_length=30, blank=False, null=False)
    user_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    date_created = models.DateTimeField(default=datetime.now())
    klucz = models.TextField(blank=True, null=True)
