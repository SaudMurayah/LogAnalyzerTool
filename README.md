# Log Analyzer Tool

The Log Analyzer Tool is a Python-based application designed to help you analyze log files for suspicious activities such as malware, unauthorized access, phishing attempts, file tampering, security breaches and more. The tool works on macOS, Windows, and Linux. It features both a user-friendly GUI and an interactive CLI mode, and generates clear reports with graphs for easy interpretation.
<p align="center">
 <img width="800" height="400" alt="LogAnalyzer" src="https://github.com/user-attachments/assets/df889e9c-db72-4101-ba83-29437b9ae51e" />
</p>



## Features
- Analyze log files for various suspicious activities.
- Provides recommended actions for detected issues.
- Allows adding new patterns and corresponding remedies.
- Generates a graphical visualization of detected issues.
- Easy-to-use graphical user interface (GUI) and command-line interface (CLI) for selecting log files and running scans

## Requirements
- Python 3.x
- Required Python libraries:
  - `matplotlib`
  - `tkinter` (macOS and Linux only)
  - `numpy`
- Virtual environment (recommended)

## Installation
  
### Clone the repository:

    git clone https://github.com/SaudMurayah/LogAnalyzerTool.git
    cd Log_analyzer
    
### For macOS and Linux

1. Ensure Python 3.x is installed. If not, install it:

    ```bash
    sudo apt-get install python3 python3-pip   # For Debian-based systems
    sudo pacman -S python python-pip          # For Arch-based systems
    brew install python                       # For macOS using Homebrew
    ```
2. Create a Virtual Environment:

 ```bash
For Linux/Macos:
python3 -m venv venv
source venv/bin/activate

For Windows: 
python3 -m venv venv
venv\Scripts\activate   
```

3. Install the required libraries:

    ```bash
    pip3 install -r requirements.txt
    ```

4. If `tkinter` is not installed, install it via this command:

    ```bash
    sudo apt-get install python3-tk           # For Debian-based systems
    sudo pacman -S tk                         # For Arch-based systems
    ```

### For Windows

1. Ensure Python 3.x is installed. If not, download and install it from the [official website](https://www.python.org/downloads/).

2. Install the required libraries:

    ```bash
    pip3 install -r requirements.txt
    ```

## Usage

1. Run the application:

    ```bash
    sudo python log_analyzer.py # Note: Must be run using sudo.
    ```

2. Using the GUI:
- Run the script and select option 1 (GUI Mode)
- Click on "Select Log File and Scan" to choose a log file.
- The analysis results will be displayed, including any detected suspicious activities and their remedies.
- The output report and graph will be saved in the same directory as the log file.

3. Using the CLI:
- Run the script and select option 2 (CLI Mode)
- Select option 1 from the menu
- Enter the full path to your log file when prompted
- Choose whether to show detailed remedies
- The analysis results will be displayed in the terminal, including any detected suspicious activities and their remedies
- The output report and graph will be saved in the same directory as the log file
  
## Example

Here is an example of the tool output in a bar graph:

<img width="1000" height="500" alt="Sample_Suspicious_log_suspicious_activity" src="https://github.com/user-attachments/assets/f90f8b82-9116-4053-a95b-3eb646959c23" />


After selecting a log file and running the analysis, you will see the detected issues and recommended actions with a bar graph.

## Future Enhancements

- **Real-time Monitoring**: Implement real-time monitoring of log files to detect suspicious activities as they happen.
- **Custom Patterns**: Allow users to define custom patterns and rules for detecting suspicious activities.
- **Integration with SIEM**: Integrate with Security Information and Event Management (SIEM) systems for advanced threat detection and incident response.

## Contributing
Feel free to fork this project and add your own detection patterns or features.
