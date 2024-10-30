# Log Analysis and Reporting Tool

## Table of Contents
- Overview
- Features
- Installation
  - Virtual Environment Setup
  - Dependencies
- Usage
  - Running the Script
  - Interacting with the Script
- Report Structure
  - Summary Report
  - Monthly Reports
  - Visualization Charts
  - Error Reporting
- Configuration and Customization
- Database Schema
- Error Handling and Logging
- Contributing
- License
- Contact

## Overview
The Log Analysis and Reporting Tool is a Python-based solution for analyzing system log files, specifically `wtmp` and `secure` logs. This tool targets user authentication events, login attempts, and sudo command executions, parsing these events into a structured SQLite database, then generating detailed and graphical HTML and PDF reports. Ideal for system administrators and forensic investigators, the tool automates data gathering and visualization of key access and activity information.

## Features
### Log Parsing and Analysis
- **Log Type Support**: Parses `wtmp` and `secure` logs, including rotated and compressed `.gz` versions.
- **Event Extraction**:
  - User login sessions from `wtmp` logs, recording username, terminal, and host.
  - Authentication attempts from `secure` logs, categorizing events as successful or failed, and logging IPs and services.
  - `sudo` command usage from `secure` logs, capturing details on the user, command, and target user.

### Reporting
- **Comprehensive HTML and PDF Reports**:
  - Summary report aggregating user activities, authentication attempts, and sudo command data.
  - Monthly reports breaking down statistics by month.
  - Error reports detailing any parsing issues or out-of-range entries.
- **Data Visualization**:
  - Visualizations generated with `matplotlib` to show login trends, authentication attempt breakdowns, and sudo command frequency.
  - Graphs include bar charts, pie charts, and activity timelines.

### Database Storage
- **SQLite Database**: Optimized storage and indexing for fast data retrieval.
- **Error Logging**: Records invalid entries for later analysis.

## Installation

### Virtual Environment Setup
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/arielarigossi/linux-wtmpreport.git
   cd linux-wtmpreport
