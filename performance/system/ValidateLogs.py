# Validates if the logged values seem consistent

import pandas as pd
import matplotlib.pyplot as plt
from LoadData import LoadData

def CalcDiff(logPath):

    df = LoadData(logPath)
    operations = list(set(df['Operation'].values)) # upload & download
    chunkScopedActions = df.loc[df['Chunk'] != '']

    chunkScopedActionsTotals = chunkScopedActions.groupby(['Operation', 'Action'], as_index=False)['Execution Time'].sum()
    
    # check that the logged total matches the calculated total with a small margin of error
    operationSummedTotals = chunkScopedActionsTotals.groupby(['Operation'], as_index=False).sum()
    operationLoggedTotals = df.loc[df['Action'] == 'total']

    res = {}
    for operation in operations:
        summedTotal = operationSummedTotals.loc[operationSummedTotals['Operation'] == operation]['Execution Time'].values[0]
        loggedTotal = operationLoggedTotals.loc[operationLoggedTotals['Operation'] == operation]['Execution Time'].values[0]
        diff = loggedTotal - summedTotal
        diffPercentage = (loggedTotal - summedTotal) / loggedTotal * 100
        # print (f'{operation}', f'{diff:.2f} / {loggedTotal:.2f}', f'({diffPercentage:.2f}%)')
        res[operation] = [diff, diffPercentage]
    return res

if __name__ == '__main__':
    fileSizes = ['5MB', '1GB']
    # blockSizes = ['32', '512', '1024', '2048', '4096', '8192']
    blockSizes = ['32', '1024', '2048', '4096', '8192']
    operations = ['upload', 'download']
    data = {}

    fig, axes = plt.subplots(nrows=len(operations)*len(fileSizes), ncols=2)
    fig.set_size_inches(18.5, 20)
    for fileSize in fileSizes:
        data[fileSize] = {
            'upload_value': [],
            'upload_percentage': [],
            'download_value': [],
            'download_percentage': []
        }

        for blockSize in blockSizes:
            res = CalcDiff(f'../../Client/logs/{blockSize}/performance_test_{fileSize}.log')
            for operation in operations:
                data[fileSize][f'{operation}_value'].append(res[operation][0])
                data[fileSize][f'{operation}_percentage'].append(res[operation][1])

    for i, operation in enumerate(operations):
        for j, fileSize in enumerate(fileSizes):
            for k, suffix in enumerate(['_value', '_percentage']):
                axes[i*2+j][k].barh(blockSizes, data[fileSize][f'{operation}{suffix}'])
                axes[i*2+j][k].set_xlabel('fileSize_blockSize')
                axes[i*2+j][k].set_ylabel(f'diff{suffix}')
                axes[i*2+j][k].set_title(f'{operation}{suffix} ({fileSize})')
    fig.savefig('./ValidateLogs/fig.png')
