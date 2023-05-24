from django.db import models

class Usuario(models.Model):
    nombre_usuario = models.CharField(max_length=30)
    contraseña = models.CharField(max_length=30)

class Servicio(models.Model):
    hostname = models.CharField(max_length=30)
    ip = models.CharField(max_length=20)
    password = models.CharField(max_length=30)

class Estados(models.Model):
    ip = models.CharField(max_length=30, primary_key=True)
    estado = models.CharField(max_length=15)

class Intentos(models.Model):
    ip = models.GenericIPAddressField(primary_key=True)
    intentos = models.PositiveIntegerField()
    fecha_ultimo_intento = models.DateTimeField()