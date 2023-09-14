import pandas as pd
import matplotlib.pyplot as plt
from LoadData import LoadData

def AnalyzeLog(logPath, figSuffix = None):
    if figSuffix:
        figSuffix = f'_{figSuffix}'

    df = LoadData(logPath)
    chunkScopedActions = df.loc[df['Chunk'] != '']
    operations = list(set(chunkScopedActions['Operation'].values)) # upload & download

    chunkScopedActionsTotals = chunkScopedActions.groupby(['Operation', 'Action'], as_index=False)['Execution Time'].sum()
    chunkScopedActionsMeans = chunkScopedActions.groupby(['Operation', 'Action'], as_index=False)['Execution Time'].mean()  
    
    fig, axes = plt.subplots(nrows=len(operations), ncols=3, constrained_layout = True)
    fig.set_size_inches(18.5, 10.5)
    for i, operation in enumerate(operations):
        operationDf = chunkScopedActionsTotals.loc[chunkScopedActionsTotals['Operation'] == operation]
        operationDf.set_index('Action').plot(y='Execution Time', kind='pie', ax=axes[i, 0], title = f'Total ({operation})')

        operationDf.plot(x='Action', y='Execution Time', kind='barh', ax=axes[i, 1], title = f'Total ({operation})')

    for i, operation in enumerate(operations):
        operationDf = chunkScopedActionsMeans.loc[chunkScopedActionsMeans['Operation'] == operation]
        operationDf.plot(x='Action', y='Execution Time', kind='barh', ax=axes[i, 2], title = f'Chunk Scoped Means ({operation})')
    fig.savefig(f'BasicAnalytics/fig{figSuffix}')
    # fig.show()

if __name__ == '__main__':
    fileSizes = ['5MB', '1GB']
    # blockSizes = ['32', '512', '1024', '2048', '4096', '8192']
    blockSizes = ['32', '512', '1024', '2048']

    for blockSize in blockSizes:
        for fileSize in fileSizes:
            AnalyzeLog(f'../../Client/logs/{blockSize}/performance_test_{fileSize}.log', f'{blockSize}_{fileSize}')
