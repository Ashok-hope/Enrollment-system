import datetime
import sys

# ANSI Colors for terminal output
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"

def log_event(category: str, message: str, level: str = "INFO"):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    
    color_map = {
        "AUTH": CYAN,
        "COURSE": BLUE,
        "INVITE": YELLOW,
        "ENROLLMENT": GREEN,
        "BLOCKCHAIN": MAGENTA,
        "SECURITY": RED,
        "SQL": YELLOW
    }
    cat_color = color_map.get(category.upper(), CYAN)
    
    level_color = GREEN if level == "INFO" else (YELLOW if level == "WARN" else RED)
    
    print(f"[{timestamp}] {cat_color}[{category.upper()}]{RESET} {level_color}{level}{RESET} - {message}", flush=True)
