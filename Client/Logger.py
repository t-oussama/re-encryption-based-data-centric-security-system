class Logger:
    def __init__(self, logId):
        self.file = open(f'./logs/{logId}.log', 'w')

    def log(self, line):
        self.file.write(line + '\n')

    def logPerformance(self, id, start, end):
        self.log(f'{id} - {end - start} - {start} - {end}')

    def sizeof_fmt(self, num, suffix="B"):
        for unit in ["", "K", "M", "G", "T", "P"]:
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Yi{suffix}"
