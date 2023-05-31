
import sys
import requests
import os

SECRET_KEY = os.environ.get('secret_key')

TOKEN = os.environ.get('token_telegram')
CHAT_ID = os.environ.get('chat_telegram')


def mandar_mensaje_bot(mensaje, token=TOKEN, chat_id=CHAT_ID):
    send_text = 'https://api.telegram.org/bot' + token + '/sendMessage?chat_id=' + chat_id + '&parse_mode=Markdown&text=' + "Tu còdigo de verificaciòn es: " + mensaje + ". No compartas este còdigo con nadie."
    response = requests.get(send_text)



if __name__ == '__main__':
    #mensaje = sys.argv[1]
    mandar_mensaje_bot(SECRET_KEY)
