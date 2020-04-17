from queue import Queue
import threading
import yara
from sys import argv
from time import sleep
# todo: install psutil

yara.set_config(max_strings_per_rule=20000, stack_size=32768)
MALWARE_RULES = '../generic/Miners.yar'
lock = threading.Lock()
#rules = yara.compile(filepath=MALWARE_RULES, includes=False)
PIDsQueue = Queue()
COUNTER = 0


class Scanner(threading.Thread):
	def mycallback(self, data):
		print('[+] Rule: {}, PID: {}, Strings: {}'.format(data.get('rule'), self._pid, data.get('strings')))

	def __init__(self):
		threading.Thread.__init__(self)
		self.rules = yara.compile(filepath=MALWARE_RULES, includes=False)

	def run(self):
		while True:
			self._pid = PIDsQueue.get()
			self.scan(self._pid)
			PIDsQueue.task_done()
			with lock:
				global COUNTER
				COUNTER += 1

	def scan(self, _pid):
		try:
			self.rules.match(pid=_pid, callback=self.mycallback, which_callbacks=yara.CALLBACK_MATCHES)
		except yara.Error:
			pass # process dead
		
				
with open('pids.txt') as f:
	for line in f.readlines():
		PIDsQueue.put(int(line.strip()))

for i in range(6):
	t = Scanner()
	t.setDaemon(True)
	t.start()

print('[!] {} PIDs loaded\n[!] Wait starting threads...'.format(PIDsQueue.qsize()))
sleep(10)

while not PIDsQueue.empty():
	print('[%] Scanned: {} | Queue size: {} | Active threads: {}'.format(COUNTER, PIDsQueue.qsize(), threading.active_count()))
	sleep(30)

PIDsQueue.join()

# killmeforthiscode


