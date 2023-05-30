from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from datetime import timezone
import proyectofinal.settings as conf
import math
import re
from bd import models
from proyectofinal import decoradores 
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime
import crypt
import os
import base64

#-----------------------------------------------------------------------------

# Practica 5 
def contra_valida(contra:str):
    # Verificar políticas de creación de contraseña
    if len(contra) < 10:        
        return True
    if not any(c.isupper() for c in contra):        
        return True #"La contraseña debe contener al menos una letra mayúscula."
    if not any(c.islower() for c in contra):        
        return True #"La contraseña debe contener al menos una letra minúscula."
    if not any(c.isdigit() for c in contra):        
        return True #"La contraseña debe contener al menos un dígito."
    if not any(not c.isalnum() for c in contra):        
        return True #"La contraseña debe contener al menos un carácter especial."
    else:
        return False

def generar_random_salt():
    bytes_aleatorios = os.urandom(16)
    salt = base64.b64encode(bytes_aleatorios).decode('utf-8')
    return salt

def generar_hashed(contra:str):
    salt = generar_random_salt()
    hasheado = crypt.crypt(contra, '$6$' + salt)
    return hasheado

@decoradores.logueado
def registrar_usuario(request):
    t = 'registroUser.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        nombre_usuario = request.POST.get('nombre_usuario', '')
        contraseña = request.POST.get('contraseña', '')

        errores = []
        if nombre_usuario.strip() == '':
            errores.append('El Usuario está vacío')
        if contraseña.strip() == '':
            errores.append('El password está vacío')
        if contra_valida(contraseña.strip()):
            errores.append('La contraseña no tiene un formato valido ( mínimo 10 carácteres, mayúsculas, minúsuclas, dígitos, al menos un carácter especial )')
        if errores:
            return render(request, t, {'errores': errores})
                

        hash = generar_hashed(contraseña.strip())
        usuario_nuevo = models.Usuario(nombre_usuario=nombre_usuario.strip(),contraseña=hash.strip())
        usuario_nuevo.save()
        return redirect('/monitoreo')
    

#------------------------------------------------------------------------------


def recuperar_info_ip(ip:str) -> models.Intentos:
    """
    Recupera información asociada a una ip, si la ip no existe se regresa una tupla vacía.

    Keyword Arguments:
    ip str ip V4
    returns: models.Intentos
    """
    try:
        registro = models.Intentos.objects.get(ip=ip)
        return  registro 
    except:
        return None


def fecha_en_intervalo(fecha_ultimo_intento:datetime, ahora:datetime, tiempo_limite:int) -> bool:
    """
    Determina si fecha_ultimo_intento está dentro del intervalo de tiempo definido por tiempo_limite.
    
    Keyword Arguments:
    fecha_ultimo_intento:datetime del registro del último intento almacenado
    ahora:datetime fecha actual del sistema                -- 
    tiempo_limite:int segundo del intervalo de tiempo             -- 
    returns: bool True si está en el intervalo 
    """
    diferencia_segundos = (ahora - fecha_ultimo_intento).seconds
    if diferencia_segundos < tiempo_limite:
        return True
    return False


def modificar_registro(registro:models.Intentos, ahora: datetime, intentos=1) -> None:
    """
    Restablece un registro de intentos con valores por defecto.

    Keyword Arguments:
    registro:models.Intentos --
    ahora:datetime hora actual del sistema
    returns: None 
    """
    registro.intentos = intentos
    registro.fecha_ultimo_intento = ahora
    registro.save()


def puede_intentar_loguearse(request, tiempo_limite=60, intentos_maximos=3) -> bool:
    """
    Determina si el cliente cuenta con intentos disponibles para loguearse.

    Keyword Arguments:
    request -- 
    returns: bool 
    """
    ip = get_client_ip(request)
    ahora = datetime.now(timezone.utc)
    registro = recuperar_info_ip(ip)
    if not registro:
        nuevo_registro = models.Intentos()
        nuevo_registro.ip = ip
        modificar_registro(nuevo_registro, ahora)
        return True
    else:
        intentos = registro.intentos
        fecha_ultimo_intento = registro.fecha_ultimo_intento
        if not fecha_en_intervalo(fecha_ultimo_intento, ahora, tiempo_limite):
            modificar_registro(registro, ahora)
         
            return True
        else:
            if intentos < intentos_maximos:
                modificar_registro(registro, ahora, intentos+1)
                return True
            else:
                modificar_registro(registro, ahora, intentos_maximos)
                return False

#------------------------------------------------------------------------------------------------------------


def credenciales_correctas(usuario, contra):
    try:
        registros = models.Usuario.objects.get(nombre_usuario=usuario, contraseña=contra)
        print (registros)
        return True
    except:
        return False



def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def login(request):
    t = 'login.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        errores = []
        usuario = request.POST.get('user', '')
        contra = request.POST.get('password', '')

        if puede_intentar_loguearse(request):

            if not usuario.strip() or not contra.strip():
                errores.append('No se pasó usuario o contraseña')
                return render(request, t, {'errores': errores})
            
            if not credenciales_correctas(usuario, contra):
                errores.append('El usuario o contraseña son inválidos')
                return render(request, t, {'errores': errores})

            request.session['logueado'] = True
            request.session['usuario'] = usuario
            return redirect('/monitoreo') 
        else:
            errores.append('Ya no tienes intentos, espera unos minutos')
            return render(request, t, {'errores': errores})

#-------------------------------------------------------------------------------------------------------

def formato_ip(ip:str):
    formato = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if re.search(formato, ip):
        return False
    else:
        return True

def ya_existe_ip(dip:str):
    registros = models.Servicio.objects.filter(ip=dip)
    if len(registros) == 0:
        return False
    return True

@decoradores.logueado
def registrar_servicio(request):
    t = 'registroSer.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        hostname = request.POST.get('hostname', '')
        ip = request.POST.get('ip', '')
        password = request.POST.get('password', '')

        errores = []
        if hostname.strip() == '':
            errores.append('El hostname está vacío')
        if ip.strip() == '':
            errores.append('La dirección ip está vacía')
        if password.strip() == '':
            errores.append('El password está vacío')
        if formato_ip(ip.strip()):
            errores.append('La dirección ip no tiene un formato valido')
        if ya_existe_ip(ip.strip()):
            errores.append('La dirección IP  ya fue registrada')
        if errores:
            return render(request, t, {'errores': errores})

        servicio_nuevo = models.Servicio(hostname=hostname.strip(), ip=ip.strip(), password=password.strip())
        servicio_nuevo.save()
        return redirect('/monitoreo')



#---------------------------------------------------------------------------------------------------------------------------------

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def serializar_servicio(serv):
    resultado = []
    for servicio in serv:
        d_servicio = {'hostname': servicio.hostname, 'ip': servicio.ip, 'password': servicio.password}
        resultado.append(d_servicio)
    return resultado

def buscar_servicios(request):
    servicios = models.Servicio.objects.all()
    return JsonResponse(serializar_servicio(servicios), safe=False)

def serializar_estados(estados):
    resultado = []
    for estado in estados:
        d_estado = {'estado': estado.estado, 'ip': estado.ip}
        resultado.append(d_estado)
    return resultado

def leer_estados(request):
    estados = models.Estados.objects.all()
    return JsonResponse(serializar_estados(estados), safe=False)

def comprobar_ip(valor):
  objects = models.Servicio.objects.all()
  for obj in objects:
    if obj.ip == valor:
      return True
  return False

@csrf_exempt
def registrar_estado(request):
    if request.method == 'POST':
        estado = request.POST.get('estado', 'Desconocido❔')
        ip = get_client_ip(request)
        if comprobar_ip(ip) == True:
            if not estado.strip():
                return JsonResponse({'status': 'False'})
            models.Estados(estado=estado, ip=ip).save()
            return JsonResponse({'status': 'True'})
    
    return JsonResponse({'status': 'False'})

def control_estados(request):
        estados = models.Estados.objects.all()
        for object in estados:
           object.estado='Desconocido❔'
           object.save()
        return JsonResponse({'status': 'True'})

@decoradores.logueado
def monitoreo(request):
    t = 'response.html'
    return render(request, t)
