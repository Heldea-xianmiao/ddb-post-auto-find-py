import importlib.util
import threading
import queue
import time

spec = importlib.util.spec_from_file_location('jianshi', r'c:\Users\李文轩\Desktop\jianshi.py')
jianshi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jianshi)

q = queue.Queue()

def out(msg):
    print(msg)

stop = threading.Event()
# run monitor_loop from 2070 to 2090 with short per-request delay
thread = threading.Thread(target=jianshi.monitor_loop, args=(2070, 1, stop, out, 2090, 0.2, None), daemon=True)
thread.start()
# wait for thread to finish
thread.join()
print('monitor_test finished')
