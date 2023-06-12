import pandas as pd

def LoadData(logPath):
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
        
    operations = ['Operation', 'Action', 'Chunk', 'Execution Time', 'Start', 'End']
    return pd.DataFrame(data, columns=operations)