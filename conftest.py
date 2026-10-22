"""pytest 配置：把项目根目录加入 sys.path。

这样无论用 `pytest` 还是 `python -m pytest`、从哪个目录调用，
`from models import ...` / `from collectors... import ...` 都能解析
（项目采用平铺布局：collectors/ engine/ 与 models.py 同级，见 SPEC 架构图）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
