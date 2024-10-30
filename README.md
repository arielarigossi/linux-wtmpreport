

## Features 
 
- **Custom Log Path** : Analyze logs from a user-specified directory.
 
- **Comprehensive Parsing** : Process `wtmp` and `secure` files, including rotated and compressed versions.
 
- **Time Range Selection** : Automatically infer or manually specify the time range for analysis.
 
- **Database Storage** : Store parsed data in an optimized SQLite database.
 
- **Graphical Reports** : Generate graphs showing login activities, authentication attempts, and `sudo` command usage.
 
- **HTML and PDF Reports** : Produce detailed reports in both HTML and PDF formats.
 
- **Error Reporting** : Identify and report malformed or out-of-range log entries.

## How It Works 

The script performs the following main steps:
 
1. **Logging Configuration** : Sets up logging to track the script's execution.
 
2. **Utility Functions** : Includes functions to solicit user input, determine time ranges, and parse log files.
 
3. **Database Initialization** : Creates an SQLite database with optimized settings and necessary tables.
 
4. **Data Parsing and Storage** : Parses `wtmp` and `secure` files, storing relevant data in the database.
 
5. **Report Generation** : Creates graphs and reports based on the parsed data.

### 1. Logging Configuration 

The script configures logging to record its operations, errors, and informational messages.


```python
logging.basicConfig(
    filename='analisis_logs.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s:%(message
```

You: 

you're not parsing the markdown code

ChatGPT: 

Thought for 41 seconds
# Log Analysis Tool 
This tool parses custom `/var/log` paths to generate reports from `wtmp` and `secure` files, including their rotated versions. It provides insights into system logins, authentication attempts, sudo commands, and more. The reports are generated in both HTML and PDF formats, complete with graphs and summaries.
## Table of Contents 
 
- [Features](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#features)
 
- [Use Cases](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#use-cases)
 
- [Installation](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#installation)  
  - [Prerequisites](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#prerequisites)
 
  - [Setting Up a Virtual Environment](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#setting-up-a-virtual-environment)
 
  - [Installing Dependencies](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#installing-dependencies)
 
- [Usage](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#usage)
 
- [How It Works](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#how-it-works)  
  - [1. Log Directory Input](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#1-log-directory-input)
 
  - [2. Time Range Determination](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#2-time-range-determination)
 
  - [3. Parsing wtmp Files](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#3-parsing-wtmp-files)
 
  - [4. Mapping and Parsing secure Files](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#4-mapping-and-parsing-secure-files)
 
  - [5. Database Initialization](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#5-database-initialization)
 
  - [6. Generating Reports](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#6-generating-reports)
 
- [Generating Reports](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#generating-reports-1)  
  - [Graphs](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#graphs)
 
  - [Summaries](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#summaries)
 
  - [Monthly Reports](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#monthly-reports)
 
  - [Error Reports](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#error-reports)
 
- [Logging](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#logging)
 
- [Contributing](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#contributing)
 
- [License](https://chatgpt.com/c/6722444a-d510-8009-8f65-aaf2314bb747#license)

## Features 
 
- **Custom Log Path** : Allows specifying a custom path to the log directory.
 
- **Rotated Logs Handling** : Supports parsing of rotated `wtmp` and `secure` log files (e.g., `wtmp.1`, `secure.1`, `secure.gz`).
 
- **Time Range Selection** : Automatically determines the time range from `wtmp` files or allows manual input.
 
- **Database Storage** : Uses SQLite for efficient data storage and retrieval.
 
- **Comprehensive Reports** : Generates detailed HTML and PDF reports, including graphs and summaries.
 
- **Error Logging** : Identifies and logs errors or malformed entries for further analysis.
 
- **Optimized Performance** : Implements batch processing and database optimizations for faster execution.

## Use Cases 
 
- **System Administrators** : Monitor login activities, authentication attempts, and `sudo` command usage.
 
- **Security Analysts** : Detect unauthorized access attempts, suspicious activities, and potential breaches.
 
- **Compliance Auditors** : Generate reports for compliance with security policies and regulations.
 
- **Developers** : Analyze system usage patterns and debug authentication issues.

## Installation 

### Prerequisites 
 
- **Python 3.6**  or higher
 
- **pip**  package manager
 
- **Access to log files** : May require root permissions to read `/var/log` files.
 
- **Virtual Environment Tool** : `venv` or `virtualenv` (recommended)

### Setting Up a Virtual Environment 

It's recommended to use a virtual environment to isolate dependencies.


```bash
# Create a virtual environment named 'env'
python3 -m venv env

# Activate the virtual environment
source env/bin/activate  # On Windows: env\Scripts\activate
```

### Installing Dependencies 
Install required Python packages using `pip`:

```bash
pip install -r requirements.txt
```
Create a `requirements.txt` file with the following content:

```
matplotlib
weasyprint
```

Additional packages may be required based on your system configuration.

## Usage 

Run the script:


```bash
python log_analysis.py
```
 
- **Log Directory** : You'll be prompted to enter the path to the log directory (default is `/var/log/`).
 
- **Time Range** : The script will attempt to determine the time range from `wtmp` files. You can confirm or input a custom range.
 
- **Processing** : The script will parse log files, store data in the database, and generate reports.
 
- **Output** : Reports and logs will be saved in a timestamped directory (e.g., `informe_logs-20230101-123456_PID1234`).

## How It Works 

### 1. Log Directory Input 
 
- **Function** : `solicitar_directorio_logs()`
 
- **Purpose** : Prompts the user for the log directory path.
 
- **Default** : If no input is provided, defaults to `/var/log/`.
 
- **Validation** : Checks if the directory exists; exits if not found.

### 2. Time Range Determination 
 
- **Function** : `determinar_rango_tiempo_wtmp(ruta)`
 
- **Purpose** : Attempts to determine the earliest and latest timestamps from `wtmp` files.
 
- **User Confirmation** : `solicitar_rango_tiempo(antigua, reciente)` allows the user to confirm or input a custom range.
 
- **Custom Input** : If automatic detection fails, `solicitar_rango_tiempo_personalizado()` prompts for manual dates.
3. Parsing `wtmp` Files 
- **Function** : `parsear_todos_wtmp(ruta, conn, desde, hasta)`
 
- **Process** : 
  - Identifies all `wtmp` files in the directory.
 
  - Parses each file using `struct` to unpack binary data.
 
  - Extracts user login entries (`PROCESO_USUARIO` type).
 
  - Stores relevant data in the `logins` table in the database.
4. Mapping and Parsing `secure` Files 
- **Mapping** : `mapear_archivos_secure(ruta, desde, hasta)` associates `secure` files with the time range.
 
- **Parsing** : `parsear_todos_secure(conn, archivos_mapeados, desde, hasta)` processes each `secure` file.
 
- **Data Extraction** :
  - Authentication attempts (both successful and failed).
 
  - `sudo` command executions.
 
- **Data Storage** : Inserts data into `intentos_autenticacion` and `comandos_sudo` tables.

### 5. Database Initialization 
 
- **Function** : `inicializar_base_datos(carpeta_salida)`
 
- **Database** : SQLite database named `analisis_logs.db`.
 
- **Tables Created** : 
  - `logins`
 
  - `intentos_autenticacion`
 
  - `comandos_sudo`
 
  - `errores`
 
- **Optimizations** : Sets PRAGMA settings for faster insertions and queries.

### 6. Generating Reports 
 
- **Graphs** : `generar_graficos(conn, carpeta_salida, desde, hasta)` generates visualizations.
 
- **Summaries** : `generar_resumen(conn, total_entradas_wtmp, total_lineas_secure)` compiles statistics.
 
- **Reports** : 
  - **Main Report** : `generar_reporte_principal()` creates an HTML report (`index.html`) with graphs and summaries.
 
  - **Monthly Reports** : `generar_reportes_mensuales()` generates detailed reports for each month.
 
  - **Error Report** : `generar_reporte_de_errores()` lists any parsing errors or malformed entries.

## Generating Reports 

### Graphs 
 
- **Login Activity by Month** : Bar chart of logins per month.
 
- **Authentication Attempts by Month** : Bar chart of authentication attempts per month.
 
- **Authentication Results** : Pie chart showing the ratio of successful to failed attempts.
 
- **`sudo` Commands by Month** : Bar chart of `sudo` commands executed per month.
 
- **Top 10 `sudo` Commands** : Horizontal bar chart of the most frequently used `sudo` commands.
 
- **Login Activity Timeline** : Line chart showing login activity over time.

### Summaries 
 
- **Total Logins** : Number of login entries.
 
- **Unique Users** : Number of distinct users who logged in.
 
- **Top Active Users** : Users with the highest number of logins.
 
- **Top IPs with Failed Authentications** : IP addresses with the most failed attempts.
 
- **Total `sudo` Commands Executed** : Count of `sudo` commands used.
 
- **Unique `sudo` Commands** : Number of different `sudo` commands executed.
 
- **Top `sudo` Commands** : Most frequently used `sudo` commands.

### Monthly Reports 
 
- **Details** : For each month, reports include:
  - Logins

  - Authentication attempts
 
  - `sudo` commands
 
- **Formats** : Generated in both HTML and PDF.

### Error Reports 
 
- **File** : `reporte_errores.txt` in the output directory.
 
- **Content** : Lists entries that were out of range or malformed during parsing.
 
- **Purpose** : Helps in identifying and troubleshooting issues with log files.

## Logging 
 
- **Configuration** : Set up at the beginning of the script.
 
- **Log File** : `analisis_logs.log`
 
- **Levels** : Includes INFO, WARNING, ERROR messages.
 
- **Usage** : Records significant events, errors, and user interactions.

## Contributing 

Contributions are welcome! Please follow these steps:
 
1. **Fork the Repository** : Create a personal fork of the repository on GitHub.
 
2. **Clone the Fork** : Clone your forked repository to your local machine.
 
3. **Create a Branch** : Make a new branch for your feature or bugfix.
 
4. **Commit Changes** : Commit your changes with clear and descriptive messages.
 
5. **Push to GitHub** : Push your changes to your fork on GitHub.
 
6. **Submit a Pull Request** : Open a pull request to merge your changes into the main repository.
