import json
import matplotlib.pyplot as plt
import numpy as np

suffix = '_1GB'
LOG = f'blockSizeBenchmark{suffix}.log'

f = open(LOG, 'r')

rawData = f.readlines()
data = []

for el in rawData:
    data.append(json.loads(el.strip()))


def visualize(data, figureName):
    dataSize = len(data)
    blockSizes = [el['blockSize'] for el in data]
    metrics = list(data[0].keys())
    # remove blocksize as it's not a metric
    metrics.remove('blockSize')
    metricsCount = len(metrics)

    fig, axs = plt.subplots(metricsCount, figsize=(18,18), constrained_layout = True)
    yPos = range(dataSize)
    cmap = plt.cm.tab10
    colors = cmap(np.arange(dataSize) % cmap.N)

    for i in range(metricsCount):
        metric = metrics[i]
        metricValues = [el[metric] for el in data]
        axs[i].barh(yPos, metricValues, color=colors)
        axs[i].set_yticks(yPos, labels=blockSizes)
        axs[i].set_title(metric)
    plt.savefig(f'{figureName}.png')

visualize(data, f'fullData{suffix}')

visualize(data[:-3], f'closeValuesOnly{suffix}')

f.close()

