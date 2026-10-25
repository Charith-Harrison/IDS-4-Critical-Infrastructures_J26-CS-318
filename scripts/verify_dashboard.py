# Smoke-test the older dashboard against its existing local model artifacts.
"""Integration smoke check of all pages using real saved model artifacts.

Run separately from the small-fixture unit suite. Streamlit's test runner needs
local loopback sockets for its asyncio event loop, even without a web server.
"""

import faulthandler
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from streamlit.testing.v1 import AppTest

from src.utils import ROOT, now, save_json


# Open the older dashboard in the test runner and check that its pages render.
def main():
    faulthandler.dump_traceback_later(45)
    app = AppTest.from_file(str(ROOT / "app/dashboard.py"), default_timeout=90).run()
    results = []
    for model in ["contextual", "baseline"]:
        app.sidebar.selectbox[0].set_value(model).run()
        for page in [
            "Security Overview",
            "Detection Events",
            "Event Investigation",
            "Model Performance",
            "System Health",
        ]:
            app.sidebar.radio[0].set_value(page).run()
            errors = [str(e.value) for e in app.exception] + [str(e.value) for e in app.error]
            print(f'{model}: {page}: {"PASS" if not errors else errors}', flush=True)
            if errors:
                raise AssertionError(errors)
            results.append({"model": model, "page": page, "passed": True})
    save_json(ROOT / "results/metrics/dashboard_verification.json", {"created_at": now(), "checks": results})
    faulthandler.cancel_dump_traceback_later()


if __name__ == "__main__":
    main()
