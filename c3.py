# Start the current Component 3 command-line tools from the repository root.
"""Component 3 entry point. No training, collection, or final-evaluation commands."""
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'component3'))
from cli import main

if __name__ == '__main__':
    main()
