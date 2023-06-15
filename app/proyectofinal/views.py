from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import logout
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
import pyotp #Para generar códigos OTP
import requests
#-----------------------------------------------------------------------------

# Practica 5 

usuario_global = None
def existe_usuario(usuario):
    """
    La función verifica si un usuario existe en la base de datos por su nombre de usuario y devuelve un
    valor booleano.
    
    :param usuario: El parámetro "usuario" es una cadena que representa el nombre de usuario de un
    usuario. 
    :return: La función `exists_user(usuario)` devuelve un valor booleano. Devuelve `Verdadero` si un
    usuario con el nombre de usuario `usuario` dado existe en el modelo `Usuario`, y `Falso` en caso
    contrario.
    """
    try:
        registro = models.Usuario.objects.get(nombre_usuario=usuario)
        return True
    except:
        return False


def contra_valida(contra:str):
    """
    La función verifica si una contraseña determinada cumple con ciertos criterios de longitud, letras
    mayúsculas y minúsculas, dígitos y caracteres especiales.
    
    :param contra: El parámetro "contra" es una cadena que representa una contraseña que debe validarse
    de acuerdo con ciertas políticas
    :type contra: str
    :return: un valor booleano (Verdadero o Falso) dependiendo de si la contraseña de entrada cumple con
    las políticas de creación de contraseñas especificadas.
    """
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
    """
    Esta función genera un salt aleatorio usando 16 bytes de datos aleatorios y lo codifica en formato
    base64.
    :return: un valor salt generado aleatoriamente como una cadena. 
    """
    bytes_aleatorios = os.urandom(16)
    salt = base64.b64encode(bytes_aleatorios).decode('utf-8')
    return salt

def generar_hashed(contra:str):
    """
    Esta función genera una contraseña cifrada usando un salt generado aleatoriamente.
    
    :param contra: El parámetro "contra" es una cadena que representa la contraseña que debe cifrarse
    :type contra: str
    :return: una versión codificada de la cadena de contraseña de entrada utilizando el algoritmo
    SHA-512 con una sal generada aleatoriamente.
    """
    salt = generar_random_salt()
    hasheado = crypt.crypt(contra, '$6$' + salt)
    return hasheado

@decoradores.logueado
def registrar_usuario(request):
    """
    Esta función registra un nuevo usuario al recibir una solicitud POST con un nombre de usuario y
    contraseña, validando la entrada y guardando el usuario en la base de datos si la entrada es válida.
    
    :param request: El objeto de solicitud representa la solicitud HTTP que el usuario ha realizado al
    servidor.
    :return: Si el método de solicitud es GET, la función devuelve la plantilla renderizada
    'registroUser.html'. 
    """

    t = 'registroUser.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        nombre_usuario = request.POST.get('nombre_usuario', '')
        contraseña = request.POST.get('contraseña', '')
        chat_id = request.POST.get('chat_id', '')
        bot_id = request.POST.get('bot_id', '')
        errores = []
        if nombre_usuario.strip() == '':
            errores.append('El Usuario está vacío')
        if contraseña.strip() == '':
            errores.append('El password está vacío')
<<<<<<< HEAD
        if chat_id.strip() == '':
            errores.append('El chat ID está vacío')
        if bot_id.strip() == '':
            errores.append('El bot ID está vacío')
        # if existe_usuario(nombre_usuario.strip()):
        #     errores.append('El usuario ya existe')
=======
        if existe_usuario(nombre_usuario.strip()):
            errores.append('El usuario ya existe')
>>>>>>> Actualización
        if contra_valida(contraseña.strip()):
            errores.append('La contraseña no tiene un formato valido ( mínimo 10 carácteres, mayúsculas, minúsuclas, dígitos, al menos un carácter especial )')
        if errores:
            return render(request, t, {'errores': errores})
                

        hash = generar_hashed(contraseña.strip())
        usuario_nuevo = models.Usuario(nombre_usuario=nombre_usuario.strip(),contraseña=hash.strip(), chat_id = chat_id.strip(), bot_token = bot_id.strip() )
        usuario_nuevo.save()
        return redirect('/monitoreo')
    
    

#------------------------------------------------------------------------------
#Eliminar Usuario

<<<<<<< HEAD
@decoradores.logueado_admin
def eliminnar_usuario(request):


    t = 'eliminarUser.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        nombre_usuario = request.POST.get('nombre_usuario', '')

        errores = []
        if nombre_usuario.strip() == '':
            errores.append('El Usuario está vacío')
        if not existe_usuario(nombre_usuario.strip()):
            errores.append('El usuario no existe')
        if errores:
            return render(request, t, {'errores': errores})
                

        usuario_eliminar = models.Usuario.objects.get(nombre_usuario=nombre_usuario)
        usuario_eliminar.delete()
        return redirect('/monitoreo')

#-----------------------------------------------------------------------------

#modificar usuario 
@decoradores.logueado
def modificar_usuario(request):
    """
    Restablece un registro de intentos con valores por defecto.

    Keyword Arguments:
    registro:models.Intentos --
    ahora:datetime hora actual del sistema
    returns: None 
    """

    t = 'actualizarUser.html'
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
        if not existe_usuario(nombre_usuario.strip()):
            errores.append('El usuario a modificar no existe')
        if contra_valida(contraseña.strip()):
            errores.append('La contraseña no tiene un formato valido ( mínimo 10 carácteres, mayúsculas, minúsuclas, dígitos, al menos un carácter especial )')
        if errores:
            return render(request, t, {'errores': errores})
                

        hash = generar_hashed(contraseña.strip())
        usuario_modificar = models.Usuario.get(nombre_usuario=nombre_usuario.strip())
        usuario_modificar.contraseña = hash.strip()
        usuario_modificar.save()
        return redirect('/monitoreo')
    

   


#---------------------------------------------------------------------------------
#Modificar servicio

@decoradores.logueado_admin
def modificar_servicio(request):

    t = 'actualizarSer.html'
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
        if not ya_existe_ip(ip.strip()):
            errores.append('La dirección IP no esta registrada')
        if errores:
            return render(request, t, {'errores': errores})

        servicio_actualizar = models.Servicio(ip=ip.strip())
        servicio_actualizar.hostname = hostname.strip()
        servicio_actualizar.save()
        servicio_actualizar.password = password.strip()
        servicio_actualizar.save()
        return redirect('/monitoreo')


=======
@decoradores.logueado
def eliminnar_usuario(request):


    t = 'eliminarUser.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        nombre_usuario = request.POST.get('nombre_usuario', '')

        errores = []
        if nombre_usuario.strip() == '':
            errores.append('El Usuario está vacío')
        if not existe_usuario(nombre_usuario.strip()):
            errores.append('El usuario no existe')
        if errores:
            return render(request, t, {'errores': errores})
                

        usuario_eliminar = models.Usuario.objects.get(nombre_usuario=nombre_usuario)
        usuario_eliminar.delete()
        return redirect('/monitoreo')

#-----------------------------------------------------------------------------

#modificar usuario 

def modificar_usuario(request):
    """
    Restablece un registro de intentos con valores por defecto.

    Keyword Arguments:
    registro:models.Intentos --
    ahora:datetime hora actual del sistema
    returns: None 
    """

    t = 'actualizarUser.html'
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
        if not existe_usuario(nombre_usuario.strip()):
            errores.append('El usuario a modificar no existe')
        if contra_valida(contraseña.strip()):
            errores.append('La contraseña no tiene un formato valido ( mínimo 10 carácteres, mayúsculas, minúsuclas, dígitos, al menos un carácter especial )')
        if errores:
            return render(request, t, {'errores': errores})
                

        hash = generar_hashed(contraseña.strip())
        usuario_modificar = models.Usuario.get(nombre_usuario=nombre_usuario.strip())
        usuario_modificar.contraseña = hash.strip()
        usuario_modificar.save()
        return redirect('/monitoreo')
    

   


#---------------------------------------------------------------------------------
#Modificar servicio

@decoradores.logueado
def modificar_servicio(request):

    t = 'actualizarSer.html'
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
        if not ya_existe_ip(ip.strip()):
            errores.append('La dirección IP no esta registrada')
        if errores:
            return render(request, t, {'errores': errores})

        servicio_actualizar = models.Servicio(ip=ip.strip())
        servicio_actualizar.hostname = hostname.strip()
        servicio_actualizar.save()
        servicio_actualizar.password = password.strip()
        servicio_actualizar.save()
        return redirect('/monitoreo')


>>>>>>> Actualización
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
    """
    La función comprueba si el nombre de usuario y la contraseña proporcionados coinciden con la
    contraseña codificada almacenada en la base de datos.
    
    :param usuario: El nombre de usuario del usuario que intenta iniciar sesión
    :param contra: El parámetro "contra" es la contraseña con la que el usuario intenta autenticarse
    :return: un valor booleano (Verdadero o Falso) dependiendo de si el nombre de usuario y la
    contraseña proporcionados coinciden con la contraseña cifrada almacenada en la base de datos.
    """
    try: 
        registro = models.Usuario.objects.get(nombre_usuario=usuario)
        hasheado = registro.contraseña
        partes = hasheado.split('$')
        complemento = '$' + partes[1] + '$' + partes[2] # parte[1] el el algoritmo, parte[2] es el salt
        if (hasheado == crypt.crypt(contra, complemento)) :
            return True
        else:
            return False
    except:
        return False




def get_client_ip(request):
    """
    Esta función recupera la dirección IP del cliente del objeto de solicitud en Python, teniendo en
    cuenta la posibilidad de un servidor proxy.
    
    :param request: El parámetro `request` es un objeto que representa una solicitud HTTP realizada a un
    servidor web. 
    :return: la dirección IP del cliente que realiza la solicitud. 
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def token_correcto(token,usuario):
    try: 
        registro = models.Usuario.objects.get(nombre_usuario=usuario)
        token_bd = registro.token_otp

        if (token_bd != '' or token != ''):
            if (token_bd == token) :
                return True
            else:
                return False
        else:
            return False
    except:
        return False

def eliminar_token(request):
    usuario = request.session.get('usuario')
    usuario = models.Usuario.objects.get(nombre_usuario=usuario)
    usuario.token_otp = ''
    usuario.save()

def generar_token():
    # Generar un secreto aleatorio para el OTP
    secreto = pyotp.random_base32()

    # Crear un objeto TOTP utilizando el secreto generado
    totp = pyotp.TOTP(secreto)

    # Obtener el código OTP actual
    codigo_otp = totp.now()
    return codigo_otp

def enviar_token(request):
    usuario = request.session.get('usuario')
    usuario = models.Usuario.objects.get(nombre_usuario=usuario)
    bot_token = usuario.bot_token

    chat_id = usuario.chat_id

    mensaje = generar_token()
    usuario.token_otp = mensaje
    usuario.save()
    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + chat_id + '&parse_mode=Markdown&text=' + ' Su token para loguearse es el siguiente: '+ mensaje
    requests.get(send_text)

    return HttpResponse("Mensaje enviado a Telegram")

decoradores.logueado
def login_token(request):
    """
    Esta función maneja el proceso de inicio de sesión, verifica las credenciales del usuario y redirige
    a diferentes páginas según el rol del usuario.
    
    :param request: El objeto de solicitud representa la solicitud HTTP actual que el usuario ha
    realizado al servidor. 
    :return: una plantilla HTML renderizada para la página de inicio de sesión. 
    """
    t = 'login_token.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        errores = []
        usuario = request.session.get('usuario')
        token_otp = request.POST.get('token_otp')
        print(token_otp)
        if puede_intentar_loguearse(request):

            if not token_otp.strip():
                errores.append('No se pasó el token correctamente')
                return render(request, t, {'errores': errores})
            
            if not token_correcto(token_otp,usuario):
                errores.append('Token inválido')
                return render(request, t, {'errores': errores})

            request.session['logueado'] = True
            request.session['usuario'] = usuario
            if (usuario == 'admin'):
                global usuario_global
                usuario_global = usuario
                eliminar_token(request)
                
                return redirect('/monitoreo') 
            else:
                eliminar_token(request)
                usuario_global = usuario
                return redirect('/servidor')
        else:
            errores.append('Ya no tienes intentos, espera unos minutos')
            return render(request, t, {'errores': errores})

def login(request):
    """
    Esta función maneja el proceso de inicio de sesión, verifica las credenciales del usuario y redirige
    a diferentes páginas según el rol del usuario.
    
    :param request: El objeto de solicitud representa la solicitud HTTP actual que el usuario ha
    realizado al servidor. 
    :return: una plantilla HTML renderizada para la página de inicio de sesión. 
    """
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
            if (usuario == 'admin'):
                return redirect('/token') 
            else:
                return redirect('/token')
        else:
            errores.append('Ya no tienes intentos, espera unos minutos')
            return render(request, t, {'errores': errores})

#-------------------------------------------------------------------------------------------------------

#logout

def logout_view(request):
    """
    La función anterior cierra la sesión del usuario y lo redirige a la página de inicio de sesión.
    
    :param request: El parámetro de solicitud es un objeto que representa la solicitud HTTP actual.
    :return: una respuesta de redireccionamiento a la URL '/login'.
    """ 
    logout(request)
    return redirect('/login')


#------------------------------------------------------------------------------------------------------
def formato_ip(ip:str):
    """
    La función comprueba si una cadena determinada tiene un formato de dirección IP válido.
    
    :param ip: El parámetro de entrada es una cadena que representa una dirección IP
    :type ip: str
    :return: un valor booleano. 
    """
    formato = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if re.search(formato, ip):
        return False
    else:
        return True

def ya_existe_ip(dip:str):
    """
    La función comprueba si una dirección IP dada ya existe en una tabla de base de datos.
    
    :param dip: El parámetro "dip" es una cadena que representa una dirección IP
    :type dip: str
    :return: La función `ya_existe_ip` devuelve un valor booleano. 
    """
    registros = models.Servicio.objects.filter(ip=dip)
    if len(registros) == 0:
        return False
    return True

def ya_existe_ip_relacion(dip:str):
    """
    La función comprueba si una dirección IP dada ya existe en una tabla de base de datos.
    
    :param dip: El parámetro "dip" es una cadena que representa una dirección IP
    :type dip: str
    :return: La función `ya_existe_ip` devuelve un valor booleano. 
    """
    registros = models.Relacion.objects.filter(ip=dip)
    if len(registros) == 0:
        return False
    return True

@decoradores.logueado_admin
def registrar_servicio(request):
    """
    Esta función registra un nuevo servicio con un nombre de host, una dirección IP y una contraseña, y
    busca errores antes de guardar el nuevo servicio en la base de datos.
    
    :param request: El objeto de solicitud representa la solicitud HTTP que el usuario realizó para
    acceder a la vista
    :return: Si el método de solicitud es GET, la función devuelve la plantilla HTML renderizada
    'registroSer.html'.
    """
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


#------------------------------------------------------------------------------
#Eliminar Servidor

<<<<<<< HEAD
@decoradores.logueado_admin
def eliminar_servidor(request):


    t = 'eliminarSer.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        ip = request.POST.get('ip', '')

        errores = []
        if ip.strip() == '':
            errores.append('La dirección ip está vacía')
        if formato_ip(ip.strip()):
            errores.append('La dirección ip no tiene un formato valido')
        if not ya_existe_ip(ip.strip()):
            errores.append('La dirección IP  no esta registrada')
        if errores:
            return render(request, t, {'errores': errores})

=======
@decoradores.logueado
def eliminar_servidor(request):


    t = 'eliminarSer.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        ip = request.POST.get('ip', '')

        errores = []
        if ip.strip() == '':
            errores.append('La dirección ip está vacía')
        if formato_ip(ip.strip()):
            errores.append('La dirección ip no tiene un formato valido')
        if not ya_existe_ip(ip.strip()):
            errores.append('La dirección IP  no esta registrada')
        if errores:
            return render(request, t, {'errores': errores})

>>>>>>> Actualización
        servicio_eliminar = models.Servicio.objects.get(ip=ip)
        servicio_eliminar.delete()
        return redirect('/monitoreo')
                
<<<<<<< HEAD
@decoradores.logueado_admin
def relacion(request):
    """
    Esta función registra un nuevo servicio con un nombre de host, una dirección IP y una contraseña, y
    busca errores antes de guardar el nuevo servicio en la base de datos.
    
    :param request: El objeto de solicitud representa la solicitud HTTP que el usuario realizó para
    acceder a la vista
    :return: Si el método de solicitud es GET, la función devuelve la plantilla HTML renderizada
    'registroSer.html'.
    """
    t = 'relacion.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        nombre_usuario = request.POST.get('nombre_usuario', '')
        ip = request.POST.get('ip', '')

        errores = []
        if nombre_usuario.strip() == '':
            errores.append('El nombre de usuario está vacío')
        if ip.strip() == '':
            errores.append('La dirección ip está vacía')
        if formato_ip(ip.strip()):
            errores.append('La dirección ip no tiene un formato valido')
        if ya_existe_ip_relacion(ip.strip()):
            errores.append('La dirección IP  ya fue registrada')
        if errores:
            return render(request, t, {'errores': errores})
        usuario = models.Usuario.objects.get(nombre_usuario=nombre_usuario.strip())
        ip_obj = models.Servicio.objects.get(ip=ip.strip())
        relacion_nueva = models.Relacion(nombre_usuario=usuario, ip=ip_obj)
        relacion_nueva.save()
        return redirect('/monitoreo')      

=======
>>>>>>> Actualización
#----------------------------------------------------------------------------------

def get_client_ip(request):
    """
    Esta función recupera la dirección IP del cliente del objeto de solicitud en Python, teniendo en
    cuenta la posibilidad de un servidor proxy.
    
    :param request: El parámetro `request` es un objeto que representa una solicitud HTTP realizada a un
    servidor web. 
    :return: la dirección IP del cliente que realiza la solicitud. 
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def serializar_servicio(ser,request):
    """
    La función serializa una lista de objetos de servicio en una lista de diccionarios que contienen sus
    atributos de nombre de host, IP y contraseña.
    
    :param serv: El parámetro "serv" es una lista de objetos que representan servicios. 
    :return: una lista de diccionarios, donde cada diccionario representa un servicio y contiene las
    claves 'hostname', 'ip' y 'password' con sus respectivos valores.
    """
    global usuario_global
    resultado = []
    #usuario = request.session.get('usuario')
    #print(usuario)
    relacion = models.Relacion.objects.all()
    
    datos = relacion.get(nombre_usuario=usuario_global)
    datos_ip = str(datos.ip).split()[1][1:-1]
    for servicio in ser:
        if servicio.ip == datos.ip.ip:
            print("servicio .ip ")
            print(servicio.ip)
            print("Relacion .ip ")
            print(datos.ip.ip)
            print(servicio.hostname)
            d_servicio = {'hostname': servicio.hostname, 'ip': servicio.ip, 'password': servicio.password}
            #d_servicio = {'nombre_usuario': relacion.nombre_usuario, 'ip': relacion.ip}
            resultado.append(d_servicio)
    print(resultado)
    return resultado

def buscar_servicios(request):
    """
    Esta función recupera todos los servicios de la base de datos y los devuelve como una respuesta
    JSON.
    
    :param request: El parámetro de solicitud es un objeto que representa la solicitud HTTP realizada
    por el cliente al servidor. 
    :return: Una respuesta JSON que contiene todos los servicios de la base de datos, serializada
    mediante la función `serializar_servicio`. 
    """

    servicios = models.Servicio.objects.all()
        
    return JsonResponse(serializar_servicio(servicios,request), safe=False)



def serializar_estados(estados):
    """
    La función serializa una lista de objetos que representan estados en una lista de diccionarios que
    contienen el nombre del estado y la dirección IP.
    
    :param estados: El parámetro "estados" es una lista de objetos que representan estados.
    :return: una lista de diccionarios, donde cada diccionario contiene los atributos "estado" e "ip" de
    un objeto en la lista "estados".
    """
    global usuario_global
    resultado = []
    #usuario = request.session.get('usuario')
    print(usuario_global)
    relacion = models.Relacion.objects.all()
    
    datos = relacion.get(nombre_usuario=usuario_global)

    for estado in estados:
        if estado.ip == datos.ip.ip:
            d_estado = {'cpu_info': estado.cpu_info, 'memoria_info':estado.memoria_info, 'disco_info':estado.disco_info,'ip': estado.ip}
            resultado.append(d_estado)
    return resultado




def leer_estados(request):
    """
    La función recupera todos los estados de una base de datos y los devuelve como una respuesta JSON.
    
    :param request: El parámetro de solicitud es un objeto que representa la solicitud HTTP realizada
    por el cliente al servidor. 
    :return: Una respuesta JSON que contiene datos serializados de todos los objetos del modelo
    "Estados".
    """
    estados = models.Estados.objects.all()
    return JsonResponse(serializar_estados(estados), safe=False)




def comprobar_ip(valor):
    """
    Esta función comprueba si una dirección IP dada existe en una lista de objetos.
    
    :param valor: El parámetro "valor" es una variable que representa el valor de una dirección IP cuya
    existencia se está comprobando en una base de datos de objetos de "Servicio"
    :return: La función `comprobar_ip` devuelve un valor booleano (`Verdadero` o `Falso`). D
    """
    objects = models.Servicio.objects.all()
    for obj in objects:
        if obj.ip == valor:
            return True
    return False



def registrar_estado(request):
    """
    Esta función registra el estado de una solicitud y su dirección IP en una base de datos si la
    solicitud es POST y la dirección IP es válida.
    
    :param request: El objeto de solicitud representa la solicitud HTTP que el servidor ha recibido del
    cliente. 
    :return: Si el método de solicitud no es POST, la función devuelve un JsonResponse con {'status':
    'False'}. 
    """
    if request.method == 'GET':
        cpu_info = request.GET.get('cpu_info', 'Desconocido')
        memoria_info = request.GET.get('memoria_info', 'Desconocido')
        disco_info = request.GET.get('disco_info', 'Desconocido')
        ip = get_client_ip(request)
        print(cpu_info + memoria_info + disco_info)
        print(ip)
        if comprobar_ip(ip):
            if not cpu_info.strip() or not memoria_info.strip() or not disco_info.strip():
                return JsonResponse({'status': 'False'})
            
            models.Estados(disco_info=disco_info, memoria_info=memoria_info, cpu_info=cpu_info, ip=ip).save()
            return JsonResponse({'status': 'True'})
    
    return JsonResponse({'status': 'False'})



def control_estados(request):
    """
    Esta función establece el atributo "estado" de todos los objetos en el modelo "Estados" en
    "Desconocido❔" y devuelve una respuesta JSON que indica el éxito.
    
    :param request: El parámetro `request` es un objeto que representa la solicitud HTTP realizada por
    el cliente al servidor. Contiene información como el método HTTP utilizado (GET, POST, etc.), los
    encabezados, los parámetros de consulta y el cuerpo de la solicitud. En esta función, el parámetro
    `request`
    :return: Una respuesta JSON con la clave "estado" y el valor "Verdadero".
    """
    estados = models.Estados.objects.all()
    for object in estados:
        object.cpu_info='Desconocido❔'
        object.memoria_info = 'Desconocido❔'
        object.disco_info = 'Desconocido❔'
        object.save()
    return JsonResponse({'status': 'True'})


@decoradores.logueado_admin
def monitoreo_admin(request):
    """
    Esta función devuelve una respuesta HTML procesada para la vista "monitoreo_admin".
    
    :param request: El parámetro de solicitud es un objeto que representa la solicitud HTTP realizada
    por el cliente al servidor.
    :return: una plantilla HTML renderizada llamada "response.html" usando la función Django render().
    """
    t = 'response.html'
    return render(request, t)


@decoradores.logueado
def monitoreo (request):
    """
    Esta función representa una plantilla HTML llamada "monitoreo.html" cuando se llama con un parámetro
    de solicitud.
    
    :param request: El parámetro de solicitud es un objeto que representa la solicitud HTTP realizada
    por el cliente al servidor. 
    :return: la plantilla HTML procesada 'monitoreo.html' en respuesta a la solicitud.
    """
    t = 'monitoreo.html'
    return render(request, t)