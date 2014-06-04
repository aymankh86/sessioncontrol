from django.db import models
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User

class SessionControl(models.Model):
    user = models.ForeignKey(User, related_name='user')
    token = models.CharField(max_length=250, blank=True, default='')
    expire_time = models.DateTimeField()
    expired = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)


