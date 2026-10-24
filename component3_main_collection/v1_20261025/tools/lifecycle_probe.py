"""Protocol-free signal exercise. Does not import/call a collector or open sockets."""
import signal
import threading
import json

if __name__=='__main__':
    stop=threading.Event()
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    print(json.dumps(dict(status='TEST_ONLY_READY',traffic_generated=False)),flush=True)
    if not stop.wait(20): raise SystemExit('Signal test timed out')
    print(json.dumps(dict(status='TEST_ONLY_INTERRUPTED',traffic_generated=False)),flush=True)
