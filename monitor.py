import curses
import time
import os

DATA_DIR = "./data"
BLOCKLIST = os.path.join(DATA_DIR, "blocklist.csv")
TRACKER = os.path.join(DATA_DIR, "ip_tracker.csv")
ALLOWLIST = os.path.join(DATA_DIR, "allowlist.csv")
HONEYPOT = os.path.join(DATA_DIR, "honeypot.csv")

def read_csv(filepath):
    if not os.path.exists(filepath):
        return []
    lines = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                lines.append(line.strip().split(","))
    except Exception:
        pass
    return lines

def main(stdscr):
    # Setup
    curses.curs_set(0)
    stdscr.nodelay(1)
    
    # Colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)

    while True:
        stdscr.erase()
        
        max_y, max_x = stdscr.getmaxyx()
        
        # Read Data
        blocklist = read_csv(BLOCKLIST)
        tracker = read_csv(TRACKER)
        allowlist = read_csv(ALLOWLIST)
        honeypot = read_csv(HONEYPOT)
        
        # Title
        title = " IPS Live Monitor "
        stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
        stdscr.addstr(0, (max_x - len(title)) // 2, title)
        stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
        
        # Active Connections (Tracker) - Top Left
        col1_x = 2
        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(2, col1_x, "Active Connections (Tracker)")
        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(3, col1_x, f"{'IP Address':<15} | {'Tokens':<6} | Drops")
        stdscr.addstr(4, col1_x, "-" * 35)
        
        y = 5
        for row in tracker[:10]: # show top 10
            if len(row) >= 4:
                ip, ts, tokens, drops = row
                stdscr.addstr(y, col1_x, f"{ip:<15} | {tokens:<6} | {drops}")
                y += 1
                
        # Blocklist - Top Right
        col2_x = max_x // 2
        stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
        stdscr.addstr(2, col2_x, "Blocklist")
        stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
        stdscr.addstr(3, col2_x, f"{'IP Address':<18} | {'Static':<6}")
        stdscr.addstr(4, col2_x, "-" * 28)
        
        y = 5
        for row in blocklist[:10]:
            if len(row) >= 4:
                ip, prefixlen, ts, is_static = row[:4]
                ip_with_prefix = f"{ip}/{prefixlen}" if prefixlen != "32" else ip
                stdscr.addstr(y, col2_x, f"{ip_with_prefix:<18} | {is_static:<6}")
                y += 1
            elif len(row) == 3: # Backwards compatibility for old CSV
                ip, ts, is_static = row
                stdscr.addstr(y, col2_x, f"{ip:<18} | {is_static:<6}")
                y += 1
                
        # Allowlist - Bottom Left
        y_bottom = 18
        stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(y_bottom, col1_x, "Allowlist")
        stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(y_bottom+1, col1_x, f"{'IP Address':<15}")
        stdscr.addstr(y_bottom+2, col1_x, "-" * 15)
        
        y = y_bottom + 3
        for row in allowlist[:5]:
            if len(row) >= 2:
                stdscr.addstr(y, col1_x, f"{row[0]:<15}")
                y += 1
                
        # Honeypot - Bottom Right
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(y_bottom, col2_x, "Honeypot")
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(y_bottom+1, col2_x, f"{'IP Address':<15}")
        stdscr.addstr(y_bottom+2, col2_x, "-" * 15)
        
        y = y_bottom + 3
        for row in honeypot[:5]:
            if len(row) >= 2:
                stdscr.addstr(y, col2_x, f"{row[0]:<15}")
                y += 1
        
        stdscr.addstr(max_y-1, 2, "Press 'q' to quit.")
        stdscr.refresh()
        
        # Check for quit
        c = stdscr.getch()
        if c == ord('q'):
            break
            
        time.sleep(1)

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
