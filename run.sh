#!/usr/bin/env bash

sleep 10 # asegurarse de que el manejador ya inició 

python -u manage.py makemigrations
python -u manage.py migrate

gunicorn --bind :8000 proyectofinal.wsgi:application --reload


