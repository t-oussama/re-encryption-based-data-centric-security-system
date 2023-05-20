import pandas as pd
import matplotlib.pyplot as plt

logPath = '../../Client/logs/performance_test_1GB.log'
# logPath = '../../Client/logs/performance_test_1GB_1684530626.258546.log'

with open(logPath, 'r') as logFile:
    lines = logFile.readlines()
    data = [] # [operation, action, chunkId, value]

    chunkIds = set()
    operations = set()
    actions = {}
    for line in lines:
        key, performance, start, end = line.strip().split(' - ')
        performance = float(performance)
        start = float(start)
        end = float(end)
        keySplit = key.split('::')
        if len(keySplit) == 2:
            operation, action = keySplit
            chunkId = ''
        else:
            operation, action, chunkId = keySplit
            chunkIds.add(chunkId)

        operations.add(operation)

        if not operation in actions:
            actions[operation] = set()
        actions[operation].add(action)

        # if not operation in data:
        #     data[operation] = {}

        # if not action in data[operation]:
        #     data[operation][action] = {}

        # if chunkId:
            # data[operation][action][chunkId] = performance
        # else:
            # data[operation][action] = performance

        data.append([operation, action, chunkId, performance, start, end])

    print('chunks count', len(chunkIds));
    print('operations', list(operations));
    for operation in operations:
        print(f'actions for {operation}', list(actions[operation]));

    
    df = pd.DataFrame(data, columns=['Operation', 'Action', 'Chunk', 'Execution Time', 'Start', 'End'])
    # print(df)

    chunkScopedActions = df.loc[df['Chunk'] != '']
    # print(chunkScopedActions)

    chunkScopedActionsTotals = chunkScopedActions.groupby(['Operation', 'Action'], as_index=False)['Execution Time'].sum()
    print(chunkScopedActionsTotals)

    chunkScopedActionsMeans = chunkScopedActions.groupby(['Operation', 'Action'], as_index=False)['Execution Time'].mean()
    
    # check that the logged total matches the calculated total with a small margin of error
    operationSummedTotals = chunkScopedActionsTotals.groupby(['Operation'], as_index=False).sum()
    print('operationSummedTotals', operationSummedTotals)
    operationLoggedTotals = df.loc[df['Action'] == 'total']
    print('operationLoggedTotals', operationLoggedTotals)
    
    fig, axes = plt.subplots(nrows=len(operations), ncols=3)
    fig.set_size_inches(18.5, 10.5)
    for i, operation in enumerate(operations):
        operationDf = chunkScopedActionsTotals.loc[chunkScopedActionsTotals['Operation'] == operation]
        operationDf.set_index('Action').plot(y='Execution Time', kind='pie', ax=axes[i, 0], title = operation)
        operationDf.plot(x = 'Action', y='Execution Time', kind='barh', ax=axes[i, 1], title = operation)

    for i, operation in enumerate(operations):
        operationDf = chunkScopedActionsMeans.loc[chunkScopedActionsMeans['Operation'] == operation]
        operationDf.plot(x = 'Action', y='Execution Time', kind='barh', ax=axes[i, 2], title = operation)
    fig.savefig('fig')
    # fig.show()