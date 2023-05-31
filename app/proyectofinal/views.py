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

#-----------------------------------------------------------------------------

# Practica 5 


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

        errores = []
        if nombre_usuario.strip() == '':
            errores.append('El Usuario está vacío')
        if contraseña.strip() == '':
            errores.append('El password está vacío')
        # if existe_usuario(nombre_usuario.strip()):
        #     errores.append('El usuario ya existe')
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
                return redirect('/monitoreo') 
            else:
                return redirect('/servidor')
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

@decoradores.logueado
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



#---------------------------------------------------------------------------------------------------------------------------------

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

def serializar_servicio(serv):
    """
    La función serializa una lista de objetos de servicio en una lista de diccionarios que contienen sus
    atributos de nombre de host, IP y contraseña.
    
    :param serv: El parámetro "serv" es una lista de objetos que representan servicios. 
    :return: una lista de diccionarios, donde cada diccionario representa un servicio y contiene las
    claves 'hostname', 'ip' y 'password' con sus respectivos valores.
    """
    resultado = []
    for servicio in serv:
        d_servicio = {'hostname': servicio.hostname, 'ip': servicio.ip, 'password': servicio.password}
        resultado.append(d_servicio)
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
    return JsonResponse(serializar_servicio(servicios), safe=False)



def serializar_estados(estados):
    """
    La función serializa una lista de objetos que representan estados en una lista de diccionarios que
    contienen el nombre del estado y la dirección IP.
    
    :param estados: El parámetro "estados" es una lista de objetos que representan estados.
    :return: una lista de diccionarios, donde cada diccionario contiene los atributos "estado" e "ip" de
    un objeto en la lista "estados".
    """
    resultado = []
    for estado in estados:
        d_estado = {'estado': estado.estado, 'ip': estado.ip}
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



@csrf_exempt
def registrar_estado(request):
    """
    Esta función registra el estado de una solicitud y su dirección IP en una base de datos si la
    solicitud es POST y la dirección IP es válida.
    
    :param request: El objeto de solicitud representa la solicitud HTTP que el servidor ha recibido del
    cliente. 
    :return: Si el método de solicitud no es POST, la función devuelve un JsonResponse con {'status':
    'False'}. 
    """
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
        object.estado='Desconocido❔'
        object.save()
    return JsonResponse({'status': 'True'})


@decoradores.logueado
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