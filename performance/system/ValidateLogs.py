# Validates if the logged values seem consistent
# This only verifies the consistency accross chunks
# with the same operation, file size and chunk size

import pandas as pd
import matplotlib.pyplot as plt
from LoadData import LoadData
from FileSizes import FILE_SIZES

def CalcDiff(logPath):

    df = LoadData(logPath)
    chunkScopedActions = df.loc[df['Chunk'] != '']
    operations = list(set(chunkScopedActions['Operation'].values)) # upload & download

    chunkScopedActionsTotals = chunkScopedActions.groupby(['Operation', 'Action'], as_index=False)['Execution Time'].sum()
    globalActionsSummed = df.loc[(df['Action'] != 'total') & (df['Chunk'] == '')].groupby(['Operation'], as_index=False)['Execution Time'].sum()
    
    # check that the logged total matches the calculated total with a small margin of error
    chunkActionsSummedTotals = chunkScopedActionsTotals.groupby(['Operation'], as_index=False).sum()
    operationSummedTotals = pd.concat([chunkActionsSummedTotals, globalActionsSummed]).groupby(['Operation'], as_index=False)['Execution Time'].sum()
    operationLoggedTotals = df.loc[df['Action'] == 'total']

    res = {}
    for operation in operations:
        summedTotal = operationSummedTotals.loc[operationSummedTotals['Operation'] == operation]['Execution Time'].values[0]
        loggedTotal = operationLoggedTotals.loc[operationLoggedTotals['Operation'] == operation]['Execution Time'].values[0]
        diff = loggedTotal - summedTotal
        diffPercentage = (loggedTotal - summedTotal) / loggedTotal * 100
        res[operation] = [diff, diffPercentage]
    return res

def CalcVariation(logPath):
    df = LoadData(logPath)
    # operations = list(set(df['Operation'].values)) # upload & download
    chunkScopedActions = df.loc[df['Chunk'] != '']
    groupedChunkScopedActions = chunkScopedActions.groupby(['Operation', 'Action'], as_index=False)
    return groupedChunkScopedActions['Execution Time'].agg(['min', 'max', 'mean', 'median', 'var'])


def dfToTable(df, width=20, height=3):
    rows = []
    for i, row in enumerate(df.values):
        row = list(row[:2]) + list(map(lambda e: f'{e:.6f}', row[2:]))
        rows.append(row)

    cols = list(df.columns)

    fig, ax = plt.subplots(constrained_layout = True)
    fig.set_size_inches(width, height)
    ax.axis('tight')
    ax.axis('off')
    table = ax.table(cellText=rows, colLabels=cols, loc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    return fig

if __name__ == '__main__':
    fileSizes = FILE_SIZES
    # blockSizes = ['1024']
    # blockSizes = ['512']
    blockSizes = ['32', '512', '1024']
    # blockSizes = ['32', '1024', '2048', '4096', '8192']
    operations = ['upload', 'download']
    data = {}

    dataFrames = []
    for fileSize in fileSizes:
        for blockSize in blockSizes:
            res = CalcVariation(f'../../Client/logs/{blockSize}/performance_test_{fileSize}.log')
            if not len(dataFrames):
                dataFrames.append(res[['Operation', 'Action']])
            newColName = f'{fileSize}_{blockSize}'
            dataFrames.append(res.rename(columns={'var': newColName})[newColName])
            fig = dfToTable(res)
            fig.savefig(f'./ValidateLogs/variance_{fileSize}_{blockSize}.png')
    globalVariances = pd.concat(dataFrames, axis=1)

    globalVariances['max_variance'] = globalVariances.iloc[:, 2:].max(axis=1)
    fig = dfToTable(globalVariances, 30, 3)
    fig.savefig(f'./ValidateLogs/variances_all.png')

    fig, axes = plt.subplots(nrows=len(operations)*len(fileSizes), ncols=2, constrained_layout = True)
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
                axes[i*2+j][k].set_ylabel('fileSize_blockSize')
                axes[i*2+j][k].set_xlabel(f'diff{suffix}')
                axes[i*2+j][k].set_title(f'{operation}{suffix} ({fileSize})')
    fig.savefig('./ValidateLogs/summed-total-vs-real-total.png')
