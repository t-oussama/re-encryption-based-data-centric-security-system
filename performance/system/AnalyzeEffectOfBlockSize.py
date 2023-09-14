import pandas as pd
import matplotlib.pyplot as plt
from LoadData import LoadData

def dfToTable(df, width=20, height=3):
    rows = []
    indexes = list(df.index)
    for i, row in enumerate(df.values):
        row = list([indexes[i]]) + list(row[:2]) + list(map(lambda e: f'{e:.6f}', row[2:]))
        rows.append(row)

    cols = ['index'] + list(df.columns)

    fig, ax = plt.subplots(constrained_layout = True)
    fig.set_size_inches(width, height)
    ax.axis('tight')
    ax.axis('off')
    table = ax.table(cellText=rows, colLabels=cols, loc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    return fig

def AnalyzeEffectOfBlockSize(dataFrames, fileSize):
    df = None
    for blockSize in dataFrames.keys():
        dataFrame = dataFrames[blockSize].groupby(['Operation', 'Action'], as_index=False)['Execution Time'].sum()
        dataFrame.rename(columns={'Execution Time': f'{blockSize}_exec_time'}, inplace=True)
        # df = pd.concat([df, dataFrame])
        if df is None:
            df = dataFrame
        else:
            df = pd.merge(df, dataFrame, how='left', left_on=['Operation','Action'], right_on=['Operation','Action'])
    totals = df.loc[df['Action'] == 'total']
    result = totals.join(totals[list(totals.columns)[2:]].agg(['min', 'max'], axis=1))
    result['diff'] = result['max'] - result['min']
    result['diff percentage'] = (result['diff'] / result['min']) * 100
    fig = dfToTable(result)
    fig.savefig(f'./EffectOfBlockSize/{fileSize}.png')


if __name__ == '__main__':
    fileSizes = ['5MB', '512MB', '1GB']
    # blockSizes = ['32', '512', '1024', '2048', '4096', '8192']
    blockSizes = ['32', '512', '1024', '2048']

    for fileSize in fileSizes:
        dataFrames = {}
        for blockSize in blockSizes:
            dataFrames[blockSize] = LoadData(f'../../Client/logs/{blockSize}/performance_test_{fileSize}.log')
        AnalyzeEffectOfBlockSize(dataFrames, fileSize)


# -> All file sizes provide the best performance using a block size of 512, heigher and lower values both result in a relatively significant increase in execution time. These results are consistent for the different file sizes we tested with.
# TODO: check why revoke access has different exec times when changing the block size. is it affected by it ????