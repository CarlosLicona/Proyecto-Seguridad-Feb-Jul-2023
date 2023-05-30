$(document).ready(function() {
    setInterval(function() {
        $.get("/buscar_servicios", function(data, status) {
            if (status == "success") {
                lista = "<div><h3>Servicios Registrados</h3>";
                for(var i = 0; i < data.length; i++) {
                    lista += "<div><h6>" + "Servicio: " + data[i].hostname + " /  Dirección: " + data[i].ip + "</h6></div>"
                }
                lista += "</div>"
                $("#servicios").html(lista);
            }
        });

    }, 2000) ;

    setInterval(function() {
        $.get("/control_estados", function(data, status) {
        });
    }, 10000) ;

    setInterval(function() {
	$.get("/leer_estados", function(data, status) {
	    if (status == "success") {
		lista = "<div>";
		let j = 4;
		console.log(j);
		for(var i = data.length - 1; i >= 0; i--) {
		    lista += "<div><h2>" + data[i].ip + " : " + data[i].estado + "</h2></div>"
		}
		lista += "</div>"
		$("#estados").html(lista);
	    }
	});
    }, 1000) ;

});
