import json
import base64
import hashlib
import subprocess
from Cryptodome.Cipher import AES
from datetime import datetime, timezone
from Cryptodome.Random import get_random_bytes

API_KEY = '142e90f743499430c1e64c43faa4ac35'
HOST_NAME = 'SIEM'
IP_ADDRESS = '10.0.1.101'
DATETIME_FORMAT = '%d %b %Y %H:%M:%S'
LOG_FILE = 'ingestLogs.log'
ENC_KEY = hashlib.sha256(b'?D(G+KbPeShVkYp3s6v9y$B&E)H@McQf').digest()

def getDateTime():
    return f'[{datetime.now().strftime(DATETIME_FORMAT)} {datetime.now(timezone.utc).astimezone().tzinfo}]\t'

def getHashValue(fileName):
    BUF_SIZE = 65536
    hashValue = hashlib.sha256()
    with open(fileName, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            hashValue.update(data)

    return hashValue.hexdigest()

def encrypt(rawData):
    BS = AES.block_size
    padValue = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    rawData = base64.b64encode(padValue(rawData).encode('utf8'))
    initVector = get_random_bytes(AES.block_size)
    cipherText = AES.new(key= ENC_KEY, mode= AES.MODE_CFB,iv= initVector)
    return base64.b64encode(initVector + cipherText.encrypt(rawData))

currentlyActiveUsers = subprocess.Popen("users", stdout = subprocess.PIPE, stderr = subprocess.PIPE)
currUsersOutput, currUsersError = currentlyActiveUsers.communicate()
usersActivityData = f"Currently logged in users: {', '.join(str(currUsersOutput, 'utf-8').strip().split(' '))}"

apiCommand = f"""curl "https://logs.logdna.com/logs/ingest?hostname={HOST_NAME}&mac=C0:FF:EE:C0:FF:EE&ip={IP_ADDRESS}&now={datetime.now().strftime('%s')}" \
-u {API_KEY}: \
-H "Content-Type: application/json; charset=UTF-8" \
-d \
'{{
  "lines":[
    {{
        "timestamp":{datetime.now().strftime('%s')},
        "line":\"{usersActivityData}\",
        "file":"example.log"
    }}
  ]
}}'"""

loggingAPI = subprocess.Popen(apiCommand, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
loggingAPIOutput, loggingAPIError = loggingAPI.communicate()
jsonOutput = json.loads(loggingAPIOutput.decode('utf-8'))

with open(LOG_FILE, 'a') as outputFile:
    data = encrypt(f'{getDateTime()} LOG: {usersActivityData}\tBATCH ID: {jsonOutput["batchID"]}')
    outputFile.write(f'{data}\n')

print(f'\n{getDateTime()} Log data sent to server successfully & stored at {LOG_FILE}.')
print(f'{getDateTime()} ({LOG_FILE}) SHA256: {getHashValue(LOG_FILE)}')
