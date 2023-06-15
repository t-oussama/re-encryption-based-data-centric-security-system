import sys

blockSize = '1024'
if len(sys.argv) > 1:
    blockSize = sys.argv[1]

config = ''
with open('./ta-config-template.yaml', 'r') as taConfigTemplateFile:
    taConfigTemplate = taConfigTemplateFile.read()
    config = taConfigTemplate.replace('$BLOCK_SIZE', blockSize)

with open('config.yaml', 'w') as configFile:
    configFile.write(config)