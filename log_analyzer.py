import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import re
import matplotlib.pyplot as plt
from collections import defaultdict
import json
import os
import argparse
import sys

patterns = {
    'malware': re.compile(r'malware|virus|trojan|ransomware', re.IGNORECASE),
    'file_tampering': re.compile(r'file tampering|unauthorized file modification', re.IGNORECASE),
    'unauthorized_access': re.compile(r'unauthorized access|login failure|invalid login|access denied', re.IGNORECASE),
    'security_breach': re.compile(r'security breach|data breach|intrusion detected|unauthorized entry', re.IGNORECASE),
    'advanced_malware': re.compile(r'zero-day|advanced persistent threat|rootkit', re.IGNORECASE),
    'phishing': re.compile(r'phishing|spear phishing|fraudulent email', re.IGNORECASE),
    'data_leakage': re.compile(r'data leakage|data exfiltration|information leak', re.IGNORECASE)
}

remedies = {
    'malware': "Remedy: Run a full system antivirus scan, isolate the affected systems, and update your antivirus software.",
    'file_tampering': "Remedy: Restore the affected files from backup, change file permissions, and monitor file integrity.",
    'unauthorized_access': "Remedy: Reset passwords, implement multi-factor authentication, and review access logs.",
    'security_breach': "Remedy: Disconnect affected systems from the network, conduct a thorough investigation, and notify affected parties.",
    'advanced_malware': "Remedy: Employ advanced threat detection tools, perform a deep system scan, and update security protocols.",
    'phishing': "Remedy: Educate users about phishing, implement email filtering solutions, and report the phishing attempt.",
    'data_leakage': "Remedy: Identify the source of the leak, implement data loss prevention solutions, and review data access policies."
}

config_file = 'log_analyzer_config.json'

def load_patterns():
    global patterns, remedies
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
            patterns.update({k: re.compile(v, re.IGNORECASE) for k, v in config.get('patterns', {}).items()})
            remedies.update(config.get('remedies', {}))

def save_patterns():
    config = {
        'patterns': {k: v.pattern for k, v in patterns.items()},
        'remedies': {k: v for k, v in remedies.items()}
    }
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def analyze_log_file(log_file):
    suspicious_activity = defaultdict(int)
    total_lines = 0
    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            try:
                for activity, pattern in patterns.items():
                    if pattern.search(line):
                        suspicious_activity[activity] += 1
            except Exception as e:
                pass
    return suspicious_activity, total_lines

def save_report(log_file, suspicious_activity, total_lines):
    report_file = log_file.replace('.log', '_output.txt')
    with open(report_file, 'w') as f:
        f.write(f'Total lines processed: {total_lines}\n\n')
        if suspicious_activity:
            for activity, count in suspicious_activity.items():
                f.write(f'{activity}: {count}\n')
                f.write(f'{remedies[activity]}\n\n')
        else:
            f.write('No suspicious activity detected.\n')
    return report_file

def plot_suspicious_activity(log_file, suspicious_activity):
    if not suspicious_activity:
        return None

    activities = list(suspicious_activity.keys())
    counts = list(suspicious_activity.values())

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(activities, counts, color='red')
    ax.set_xlabel('Activity Type')
    ax.set_ylabel('Count')
    ax.set_title('Suspicious Activity Detected in Logs')

    graph_file = log_file.replace('.log', '_suspicious_activity.png')
    fig.savefig(graph_file)
    plt.close(fig)
    return graph_file

def cli_analyze(log_file, output_report=True, output_graph=True, verbose=False):
    """Analyze log file via CLI"""
    if not os.path.exists(log_file):
        print(f"Error: Log file '{log_file}' not found.")
        return
    
    print(f"Analyzing log file: {log_file}")
    suspicious_activity, total_lines = analyze_log_file(log_file)
    
    print(f"\nTotal lines processed: {total_lines}")
    
    if suspicious_activity:
        print("\n⚠️  SUSPICIOUS ACTIVITY DETECTED ⚠️\n")
        for activity, count in suspicious_activity.items():
            print(f"  • {activity}: {count} occurrence(s)")
            if verbose:
                print(f"    {remedies[activity]}\n")
    else:
        print("\n✓ No suspicious activity detected.\n")
    
    if output_report:
        report_file = save_report(log_file, suspicious_activity, total_lines)
        print(f"Report saved to: {report_file}")
    
    if output_graph and suspicious_activity:
        graph_file = plot_suspicious_activity(log_file, suspicious_activity)
        print(f"Graph saved to: {graph_file}")

def cli_add_pattern():
    """Add custom pattern via CLI"""
    print("\n=== Add Custom Pattern ===")
    pattern_name = input("Enter pattern name: ").strip()
    if not pattern_name:
        print("Error: Pattern name cannot be empty.")
        return
    
    pattern_regex = input("Enter regex pattern: ").strip()
    if not pattern_regex:
        print("Error: Regex pattern cannot be empty.")
        return
    
    remedy = input("Enter remedy (optional): ").strip()
    
    try:
        patterns[pattern_name] = re.compile(pattern_regex, re.IGNORECASE)
        remedies[pattern_name] = remedy if remedy else "Custom pattern remedy not provided."
        save_patterns()
        print(f"✓ Custom pattern '{pattern_name}' added successfully.")
    except re.error as e:
        print(f"Error: Invalid regex pattern - {e}")

def cli_list_patterns():
    """List all patterns via CLI"""
    print("\n=== Available Patterns ===\n")
    for name, pattern in patterns.items():
        print(f"  • {name}")
        print(f"    Pattern: {pattern.pattern}")
        print(f"    Remedy: {remedies.get(name, 'N/A')}\n")

def cli_interactive():
    """Interactive CLI mode"""
    print("\n" + "="*50)
    print("    LOG ANALYZER - Interactive Mode")
    print("="*50 + "\n")
    
    while True:
        print("\nOptions:")
        print("  1. Analyze log file")
        print("  2. Add custom pattern")
        print("  3. List all patterns")
        print("  4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            log_file = input("Enter path to log file: ").strip()
            verbose = input("Show remedies? (y/n): ").strip().lower() == 'y'
            cli_analyze(log_file, verbose=verbose)
        elif choice == '2':
            cli_add_pattern()
        elif choice == '3':
            cli_list_patterns()
        elif choice == '4':
            print("\nExiting...")
            break
        else:
            print("Invalid choice. Please try again.")


def run_analysis():
    log_file = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log Files", "*.log")])
    if not log_file:
        return

    suspicious_activity, total_lines = analyze_log_file(log_file)
    report_file = save_report(log_file, suspicious_activity, total_lines)
    graph_file = plot_suspicious_activity(log_file, suspicious_activity)

    result_message = f"Analysis complete!\nReport saved to: {report_file}"
    if graph_file:
        result_message += f"\nGraph saved to: {graph_file}"
        display_graph(graph_file)

    if suspicious_activity:
        alert_message = "Suspicious activity detected!"
        messagebox.showwarning("Alert", alert_message)

    messagebox.showinfo("Analysis Complete", result_message)
    update_analysis_results(suspicious_activity, total_lines)

def display_graph(graph_file):
    img = tk.PhotoImage(file=graph_file)
    img_label.config(image=img)
    img_label.image = img

def update_analysis_results(suspicious_activity, total_lines):
    for widget in analysis_results_frame.winfo_children():
        widget.destroy()
    
    tk.Label(analysis_results_frame, text=f"Total lines processed: {total_lines}", font=("Helvetica", 12)).pack(pady=5)
    
    if suspicious_activity:
        for activity, count in suspicious_activity.items():
            tk.Label(analysis_results_frame, text=f'{activity}: {count}', font=("Helvetica", 12)).pack(pady=2)
            tk.Label(analysis_results_frame, text=f'{remedies[activity]}', font=("Helvetica", 10)).pack(pady=2)
    else:
        tk.Label(analysis_results_frame, text='No suspicious activity detected.', font=("Helvetica", 12)).pack(pady=5)

def quit_application():
    root.quit()
    
def add_custom_pattern():
    pattern_name = simpledialog.askstring("Input", "Enter the name of the custom pattern:")
    pattern_regex = simpledialog.askstring("Input", "Enter the regex for the custom pattern:")
    if pattern_name and pattern_regex:
        try:
            patterns[pattern_name] = re.compile(pattern_regex, re.IGNORECASE)
            remedies[pattern_name] = "Custom pattern remedy not provided."
            save_patterns()
            messagebox.showinfo("Success", "Custom pattern added successfully.")
        except re.error:
            messagebox.showerror("Error", "Invalid regex pattern.")

def create_gui():
    global root, tab_analysis, tab_custom_patterns, analysis_results_frame, img_label

    print("Creating GUI...")
    root = tk.Tk()
    root.title("Log Analyzer")
    root.geometry("800x600")

    tab_control = ttk.Notebook(root)
    tab_analysis = ttk.Frame(tab_control)
    tab_custom_patterns = ttk.Frame(tab_control)
    
    tab_control.add(tab_analysis, text='Log Analysis')
    tab_control.add(tab_custom_patterns, text='Custom Patterns')
    tab_control.pack(expand=1, fill='both')

    tk.Label(tab_analysis, text="Log Analyzer Tool", font=("Helvetica", 16)).pack(pady=10)
    tk.Button(tab_analysis, text="Select Log File and Scan", command=run_analysis, font=("Helvetica", 12)).pack(pady=10)
    tk.Button(tab_analysis, text="Quit", command=quit_application, font=("Helvetica", 12)).pack(pady=10)
    
    analysis_results_frame = ttk.Frame(tab_analysis)
    analysis_results_frame.pack(pady=10, padx=10, fill='both', expand=True)

    img_label = tk.Label(tab_analysis)
    img_label.pack(pady=10)

    tk.Label(tab_custom_patterns, text="Custom Pattern Management", font=("Helvetica", 16)).pack(pady=10)
    tk.Button(tab_custom_patterns, text="Add Custom Pattern", command=add_custom_pattern, font=("Helvetica", 12)).pack(pady=10)

    print("Starting main loop...")
    root.mainloop()

def choose_mode():
    """Ask user to choose between CLI or GUI mode"""
    print("\n" + "="*50)
    print("         LOG ANALYZER TOOL")
    print("="*50)
    print("\nPlease choose how you want to run the application:\n")
    print("  1. GUI Mode (Graphical Interface)")
    print("  2. CLI Mode (Command Line Interface)")
    print("\n" + "="*50)
    
    while True:
        choice = input("\nEnter your choice (1 or 2): ").strip()
        
        if choice == '1':
            return 'gui'
        elif choice == '2':
            return 'cli'
        else:
            print("Invalid choice! Please enter 1 or 2.")

def main():
    load_patterns()
    
    
    mode = choose_mode()
    
    if mode == 'gui':
        print("\nStarting GUI mode...")
        print("Loading patterns...")
        print("Patterns loaded.")
        create_gui()
        print("GUI created.")
    else:
        cli_interactive()

if __name__ == '__main__':
    main()
