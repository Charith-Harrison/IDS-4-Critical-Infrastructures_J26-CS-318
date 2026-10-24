"""Vendored unchanged selected helpers from frozen v0.1; see evidence/vendor_receipt.json."""
from pathlib import Path
import platform, shutil, queue, threading, subprocess, time, signal, json
PORT = 15020


class JsonLines:
    def __init__(self, path: Path):
        self.file = path.open("x", encoding="utf-8")

    def append(self, data: dict) -> None:
        self.file.write(json.dumps(data) + "\n")
        self.file.flush()

    def close(self) -> None:
        self.file.close()


class Capture:
    def __init__(self, folder: Path):
        if platform.system() != "Linux" or shutil.which("tcpdump") is None:
            raise RuntimeError("Captured pilot requires Linux/tcpdump. Use Docker, or smoke for code checks only.")
        self.log_path = folder / "capture.log"
        self.log = self.log_path.open("x", encoding="utf-8")
        self.lines = queue.Queue()
        self.process = subprocess.Popen(
            ["tcpdump", "-i", "lo", "-p", "-n", "-U", "-s", "0", "-Z", "root", "-w",
             str(folder / "capture.pcap"), "tcp", "port", str(PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.reader = threading.Thread(target=self.drain, daemon=True)
        self.reader.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=0.2)
            except queue.Empty:
                if self.process.poll() is not None:
                    break
                continue
            if "listening on" in line:
                return
        self.stop()
        raise RuntimeError("tcpdump never confirmed capture readiness; read capture.log")

    def drain(self):
        for line in self.process.stderr:
            self.log.write(line)
            self.log.flush()
            self.lines.put(line)

    def stop(self) -> int:
        if self.process.poll() is None:
            # Allow libpcap to drain its bounded buffer before final statistics.
            time.sleep(1.2)
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(timeout=3)
        self.log.close()
        return self.process.returncode

