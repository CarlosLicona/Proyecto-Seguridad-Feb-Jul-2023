from django.db import models


class Usuario(models.Model):
    nombre_usuario = models.CharField(max_length=30, primary_key=True)
    contraseña = models.CharField(max_length=254)
    chat_id = models.CharField(max_length=70)
    bot_token = models.CharField(max_length=70)
    token_otp = models.CharField(max_length=10, default='', blank=True)

class Servicio(models.Model):
    hostname = models.CharField(max_length=30)
    ip = models.CharField(max_length=20, primary_key=True)
    password = models.CharField(max_length=30)

class Estados(models.Model):
    ip = models.CharField(max_length=30, primary_key=True)
    disco_info = models.CharField(max_length=15)
    cpu_info = models.CharField(max_length=15)
    memoria_info = models.CharField(max_length=15)
    

class Intentos(models.Model):
    ip = models.CharField(max_length=30, primary_key=True)
    intentos = models.PositiveIntegerField()
    fecha_ultimo_intento = models.DateTimeField()

class Relacion(models.Model):
    nombre_usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    ip = models.ForeignKey(Servicio, on_delete=models.CASCADE)