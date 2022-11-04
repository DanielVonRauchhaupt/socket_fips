import re
import os

print(os.getcwd())


with open('log.txt','r') as file:

    line = file.readline()

    while(line!=''):
        print(re.search('Payload = 2\d{2}',line))
        line = file.readline()