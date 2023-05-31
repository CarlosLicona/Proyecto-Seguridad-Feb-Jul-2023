FROM python:3.11


RUN mkdir /requerimientos
COPY ./requirements.txt /requerimientos
WORKDIR /requerimientos
RUN  pip install -r requirements.txt
RUN mkdir /code
WORKDIR /code
RUN mkdir /start
COPY ./run.sh /start
RUN chmod +x /start/run.sh

RUN useradd limitado -s /bin/bash

USER limitado

ENV MYSQL_ROOT_PASSWORD=""
ENV MYSQL_DATABASE=""
ENV secret_key=""
ENV db_name=""
ENV db_user=""
ENV db_password=""
ENV db_host=""
ENV db_port=""
ENV token_telegram=""
ENV chat_telegram=""


CMD /start/run.sh
