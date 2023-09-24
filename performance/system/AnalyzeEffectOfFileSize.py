import pandas as pd
import matplotlib.pyplot as plt
from LoadData import LoadData
from FileSizes import FILE_SIZES

def dfToTable(df, width=20, height=3):
    rows = []
    indexes = list(df.index)
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

def AnalyzeEffectOfFileSize(dataFrames):
    # Merge dataframes
    df = None
    fileSizes = dataFrames.keys()
    for fileSize in fileSizes:
        dataFrame = dataFrames[fileSize].groupby(['Operation', 'Action'], as_index=False)['Execution Time'].sum()
        dataFrame.rename(columns={'Execution Time': f'{fileSize}_exec_time'}, inplace=True)
        # df = pd.concat([df, dataFrame])
        if df is None:
            df = dataFrame
        else:
            df = pd.merge(df, dataFrame, how='left', left_on=['Operation','Action'], right_on=['Operation','Action'])

    execTimeColumns = list(map(lambda fileSize: f'{fileSize}_exec_time', fileSizes))
    # df = (df[execTimeColumns]-df[execTimeColumns].mean(axis=1))/df[execTimeColumns].std(axis=1)
    # print(df)

    for index, row in df.iterrows():
        executionTimes = list(map(lambda fileSize: row[f'{fileSize}_exec_time'], fileSizes))
        plt.plot(fileSizes, executionTimes, 'o-', label=f'{row["Operation"]}-{row["Action"]}')
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))
    plt.savefig('./EffectOfFileSize/plain.png', bbox_inches='tight')
    plt.clf()

    # normalized execution times
    for index, row in df.iterrows():
        # get the max & min from the row
        rowMax = row[execTimeColumns].max()
        rowMin = row[execTimeColumns].min()

        normalizedRow = (row[execTimeColumns] - rowMin) / (rowMax - rowMin)
        normalizedExecutionTimes = list(map(lambda fileSize: normalizedRow[f'{fileSize}_exec_time'], fileSizes))
        plt.plot(fileSizes, normalizedExecutionTimes, 'o-', label=f'{row["Operation"]}-{row["Action"]}')
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))
    plt.savefig('./EffectOfFileSize/normalized.png', bbox_inches='tight')
    plt.clf()

    # check colinearity
    # calculate area of the triangle formed by our 3 points
    # df['area'] = df.apply(lambda row: (0.5 * (1 * (row[execTimeColumns[1]] - row[execTimeColumns[2]]) + 2 * (row[execTimeColumns[2]] - row[execTimeColumns[0]]) + 3 * (row[execTimeColumns[0]] - row[execTimeColumns[1]])))
    #                       , axis=1)
    slopes = pd.DataFrame()
    slopes['slope1'] = df.apply(lambda row: ( (1/(512 - 5)) * (row[execTimeColumns[1]] - row[execTimeColumns[0]]) ), axis=1)
    slopes['slope2'] = df.apply(lambda row: ( (1/(1024 - 5)) * (row[execTimeColumns[2]] - row[execTimeColumns[0]]) ), axis=1)
    slopes['slope3'] = df.apply(lambda row: ( (1/(1024 - 512)) * (row[execTimeColumns[2]] - row[execTimeColumns[1]]) ), axis=1)
    df['max_slope_diff'] = slopes[['slope1', 'slope2', 'slope3']].max(axis=1) - slopes[['slope1', 'slope2', 'slope3']].min(axis=1)
    fig = dfToTable(df, 20, 10)
    fig.savefig('./EffectOfFileSize/table.png', bbox_inches='tight')
    plt.clf()

    # graph per action
    for index, row in df.iterrows():
        executionTimes = list(map(lambda fileSize: row[f'{fileSize}_exec_time'], fileSizes))
        plt.plot(fileSizes, executionTimes, 'o-')
        plt.savefig(f'./EffectOfFileSize/ByAction/{row["Operation"]}-{row["Action"]}.png')
        plt.clf()

    totals = df.loc[df['Action'] == 'total']
    executionTimes = list(map(lambda fileSize: totals[f'{fileSize}_exec_time'], fileSizes))
    plt.plot(fileSizes, executionTimes, 'o-')
    plt.legend(totals['Operation'])
    plt.savefig(f'./EffectOfFileSize/totals.png')
    plt.clf()

if __name__ == '__main__':
    fileSizes = FILE_SIZES
    blockSize = '512'

    dataFrames = {}
    for fileSize in fileSizes:
        dataFrames[fileSize] = LoadData(f'../../Client/logs/{blockSize}/performance_test_{fileSize}.log')
    AnalyzeEffectOfFileSize(dataFrames)

