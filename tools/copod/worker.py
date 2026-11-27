import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from apt_agent.screening.worker import main
if __name__=="__main__":
 raise SystemExit(main('rank_copod_candidates',Path(__file__).with_name("tool.json")))
