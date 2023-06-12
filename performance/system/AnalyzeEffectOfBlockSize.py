import pandas as pd
import matplotlib.pyplot as plt
from LoadData import LoadData

def AnalyzeEffectOfBlockSize(logPath, figSuffix = None):
    if figSuffix:
        figSuffix = f'_{figSuffix}'

    df = LoadData(logPath)
    print(df)


if __name__ == '__main__':
    fileSizes = ['5MB', '1GB']
    # blockSizes = ['32', '512', '1024', '2048', '4096', '8192']
    blockSizes = ['32', '1024', '2048', '4096', '8192']

    for blockSize in blockSizes:
        for fileSize in fileSizes:
            AnalyzeEffectOfBlockSize(f'../../Client/logs/{blockSize}/performance_test_{fileSize}.log', f'{blockSize}_{fileSize}')
            exit(0)
