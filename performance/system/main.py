from performance.system.BasicAnalytics import AnalyzeLog
from FileSizes import FILE_SIZES

fileSizes = FILE_SIZES
blockSizes = ['32', '512', '1024']
# blockSizes = ['32', '1024', '2048', '4096', '8192']

for blockSize in blockSizes:
    for fileSize in fileSizes:
        AnalyzeLog(f'../../Client/logs/{blockSize}/performance_test_{fileSize}.log', f'{blockSize}_{fileSize}')
