![](https://img.shields.io/badge/python-2.7-blue.svg) ![](https://img.shields.io/badge/platform-windows-lightgrey.svg)

# FolderMonitor
Monitors a Windows folder and its subfolders using Windows usage auditing and event log parsing.

OS: Windows
Python: 2.7

## Usage
This small script can be packaged into an executable with pyinstaller.

The executable should be set to run using Task Scheduler, and will then create and append to an output.csv file in the same folder as the exectuble. This output is based on the parsing of audit events in the Windows Event log. 

To set up logging of usage of a folder, set up auditing for the folder in it's properties.
