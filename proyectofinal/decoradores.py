from django.shortcuts import redirect

def logueado(funcion_decorada):
    """
    Decorador para revisar si un usuario está loguedo.

    Keyword Arguments:
    funcion_decorada -- 
    returns: fun
    """
    def interna(request, *args, **kwars):
        if not request.session.get('logueado', False):
            return redirect('/login')
        return funcion_decorada(request, *args, **kwars)

    return interna
