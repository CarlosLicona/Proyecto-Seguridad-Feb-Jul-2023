$(document).ready(function() {
    var btnGenerarToken = $('#btn-generartoken');
    var tiempoBloqueo = 180; // 3 minutos en segundos
    var bloqueado = false;
  
    btnGenerarToken.click(function() {
      if (!bloqueado) {
        bloquearBoton();
        // Realizar la solicitud AJAX a la vista de Django
        $.ajax({
          url: 'mensaje_telegram',  // Reemplaza '/ruta-de-tu-vista/' por la URL de tu vista de Django
          type: 'GET',
          success: function(response) {
            // Manejar la respuesta del servidor si es necesario
            console.log('Solicitud exitosa');
          },
          error: function(xhr, errmsg, err) {
            // Manejar errores en la solicitud AJAX si es necesario
            console.log('Error en la solicitud');
          }
        });
  
        // Iniciar el contador de bloqueo
        var contador = setInterval(function() {
          tiempoBloqueo--;
          if (tiempoBloqueo <= 0) {
            desbloquearBoton();
            clearInterval(contador);
          }
        }, 1000); // Actualizar cada segundo (1000 ms)
      }
    });
  

    function bloquearBoton() {
      btnGenerarToken.attr('disabled', true);
      bloqueado = true;
    }
  
    function desbloquearBoton() {
      btnGenerarToken.attr('disabled', false);
      bloqueado = false;
    }
  });
  