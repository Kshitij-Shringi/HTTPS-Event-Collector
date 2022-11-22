import os
import base64
import hashlib
import requests
from Cryptodome.Cipher import AES
from datetime import datetime, timezone
from Cryptodome.Random import get_random_bytes

LOG_FILE = 'ingestLogs.log'
ACCESS_LOGS = 'accessLog.log'
DATETIME_FORMAT = '%d %b %Y %H:%M:%S'
ENC_KEY = hashlib.sha256(b'?D(G+KbPeShVkYp3s6v9y$B&E)H@McQf').digest()

def getDateTime():
    return f'[{datetime.now().strftime(DATETIME_FORMAT)} {datetime.now(timezone.utc).astimezone().tzinfo}]\t'

def decrypt(encryptedData):
    unpadValue = lambda s: s[:-ord(s[-1:])]
    encryptedData = base64.b64decode(encryptedData)
    initVector = encryptedData[:AES.block_size]
    cipherText = AES.new(ENC_KEY, AES.MODE_CFB, initVector)
    return unpadValue(base64.b64decode(cipherText.decrypt(encryptedData[AES.block_size:])).decode('utf8'))

if __name__ == "__main__":
    ipAddress = requests.get('https://api.ipify.org').content.decode('utf8')
    if os.getlogin() in ['rushilchoksi']:
        with open(ACCESS_LOGS, 'a') as failedAttemptLog:
            failedAttemptLog.write(f'{getDateTime()}STATUS: SUCCESS\tUSER: {os.getlogin()}\tIP: {ipAddress}\n')

        with open(LOG_FILE, 'r') as logsFile:
            logContent = logsFile.readlines()
            for logData in logContent:
                print(decrypt(bytes(logData.strip()[2:-1], 'utf-8')))
    else:
        with open(ACCESS_LOGS, 'a') as failedAttemptLog:
            failedAttemptLog.write(f'{getDateTime()}STATUS: FAILURE\tUSER: {os.getlogin()}\tIP: {ipAddress}\n')

        print(f'You are not authorized to use this application, this action will be reported.')
