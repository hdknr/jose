from django.db import models


class Key(models.Model):
    entity = models.CharField(max_length=200)
    uri = models.CharField(max_length=200)
    data = models.TextField()
