# 🚦 APK Security Guard MCP Suite

[![Platform](https://img.shields.io/badge/platform-Android-green.svg)](https://www.android.com/)

---

## 📝 Project Introduction

This project aims to provide a one-stop automated solution for Android APK security analysis and vulnerability detection. By integrating mainstream decompilation, static analysis, dynamic analysis and other tools such as JEB, JADX, APKTOOL, FlowDroid, MobSF, etc., and unifying them into MCP (Model Context Protocol) standard API interfaces, the automation and efficiency of security analysis are greatly improved. It is suitable for security researchers, penetration testers, developers and other users who have requirements for APK security.

---

## 🎬 Effect display
![效果演示](demo.gif)
---

## ⚙️ Configuration Instructions

### 🧩 Install Dependencies

To avoid dependency conflicts in the global environment, it is highly recommended to use a Python virtual environment for managing project dependencies. Here are the detailed installation steps:

1. Create a new virtual environment:
```bash
# For Windows
python -m venv myenv
myenv\Scripts\activate

# For Linux/MacOS
python -m venv myenv
source myenv/bin/activate
```

2. After confirming the virtual environment is activated (you should see `(myenv)` in your command prompt), install the project dependencies:
```bash
pip install -r requirements.txt
```

3. If you need to use MobSF related APIs, install Node.js dependencies separately, navigate to the `MobSF-MCP` directory:
```bash
npm install -g mobsf-mcp
```

> 📝 **Notes**:
> - Python 3.11 is recommended
> - Remember to activate the virtual environment each time you start a new working session

---
### 📦 Plugin or Script Installation Recommendations

#### JEB MCP Script

The script needs to be placed in the scripts folder of the JEB tool in advance.

1. Open JEB and navigate to `File > Scripts > Script Selector`.
2. Select and run `MCP.py` from your script list.
3. If the script is loaded and running successfully, you should see the following messages in the JEB output console:

```
[MCP] Plugin loaded
[MCP] Plugin running
[MCP] Server started at http://localhost:16161
```
---

#### JADX MCP Plugin

- **Java 17 is required** for building and running the plugin.
- In the `JADX-MCP` root directory, run:
  ```bash
  ./gradlew build
  ```
- After building, the plugin JAR will be generated at:
  ```
  plugin/build/libs/JADX-MCP-Plugin.jar
  ```
- Alternatively, you can directly use the pre-built JAR package:
  [Download JADX-MCP-Plugin.jar](https://github.com/nkcc-apk/APK-Security-Guard-MCP-Suite/blob/main/JADX-MCP/JADX-MCP-Plugin.jar )
- Copy the JAR file to the `lib` folder of your `jadx-gui` installation:
  ```
  cp plugin/build/libs/JADX-MCP-Plugin.jar <path-to-jadx-gui>/lib/
  ```

---

#### APKTOOL 

To install APKTool on Windows, you can use Chocolatey (a popular Windows package manager):

> Open PowerShell as Administrator.

1. Install Chocolatey by running the following command:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

2. Once Chocolatey is installed, install APKTool with:

```powershell
choco install apktool
```

After installation, you can use `apktool` directly from the command line. For more details and advanced usage, please refer to the [official APKTool documentation](https://github.com/iBotPeaches/Apktool).

---

#### MobSF MCP

First make sure [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) is installed.


If you wish to extend the functionality and add new APIs, run the following command in the `MobSF-MCP` root directory of your project:
  ```bash
  npm run build
  ```

  Once the build is complete, you will find the generated `index.js` and `mobsf.js` files in the build folder.
> Open PowerShell as Administrator.

- Set the required environment variables in your command line:
  ```bash
  $env:MOBSF_URL="http://localhost:8000"; 
  $env:MOBSF_API_KEY="your_api_key_here"; 
  ```
- Start the MobSF MCP server with:
  ```bash
  npx mobsf-mcp
  ```

---

#### FlowDroid 

To set up FlowDroid for use with this suite:

1. Download the FlowDroid`soot-infoflow-cmd-2.13.0-jar-with-dependencies.jar` command-line JAR from the [official releases page](https://github.com/secure-software-engineering/FlowDroid/releases).

2. In the `FlowDroid-MCP` directory, locate the `.env` file. Open it with a text editor and configure the path to your FlowDroid JAR. For example:

```
FLOWDROID_WORKSPACE=../flowdroid_workspace
FLOWDROID_JAR_PATH=/home/user/tools/flowdroid/flowdroid.jar
JAVA_HOME=/usr/lib/jvm/java-11-openjdk
```


In the `flowdroid_mcp.py` script, FlowDroid relies on several key environment variables to run. Make sure these variables are configured correctly before running the script.

```python
# line 15-18 
FLOWDROID_WORKSPACE = os.getenv("FLOWDROID_WORKSPACE", "flowdroid_workspace")
FLOWDROID_JAR_PATH = os.getenv("FLOWDROID_JAR_PATH", "FlowDroid.jar")
JAVA_HOME = os.getenv("JAVA_HOME")

# line 134-144
command = [
    "java",
    "-jar",
    FLOWDROID_JAR_PATH,  # Make sure the path is correct
    "-a", apk_path,
    "-o", output_dir,
    "-p", "Android\\Sdk\\platforms",  # The platforms directory must be specified
    "-s", "FlowDroid-MCP\\script\\SourcesAndSinks.txt",  # You must specify a source/sink file
]
```

> 📝 **Notes**:
> - Replace all paths with your actual system paths
> - Ensure Android SDK platforms directory is correctly specified

---

### 🖥️ VSCode Cline Extension Configuration

To use this project with the [cline](https://marketplace.visualstudio.com/items?itemName=cline-tools.cline) extension in VSCode, add the following configuration to your cline configuration file:

```json
{
  "mcpServers": {
    "Jadx MCP Server": {
      "disabled": false,
      "timeout": 60,
      "command": "myenv\\Scripts\\python.exe",
      "args": [
        "JADX-MCP\\fastmcp_adapter.py"
      ],
      "transportType": "stdio"
    },
    "JEB MCP Server": {
      "disabled": false,
      "timeout": 1800,
      "command": "myenv\\Scripts\\python.exe",
      "args": [
        "JEB-MCP\\server.py"
      ],
      "transportType": "stdio"
    },
    "FlowDroid MCP Server": {
      "disabled": false,
      "timeout": 60,
      "command": "myenv\\Scripts\\python.exe",
      "args": [
        "FlowDroid-MCP\\script\\flowdroid_mcp.py"
      ],
      "transportType": "stdio"
    },
    "MobSF MCP Server": {
      "disabled": false,
      "timeout": 60,
      "command": "Nodejs\\node.exe",
      "args": [
        "MobSF-MCP\\build\\index.js"
      ],
      "env": {
        "MOBSF_URL": "http://localhost:8000",
        "MOBSF_API_KEY": "your_api_key_here"
      },
      "transportType": "stdio"
    },
    "APKTOOL MCP Server": {
      "disabled": false,
      "timeout": 60,
      "command": "myenv\\Scripts\\python.exe",
      "args": [
        "APKTOOL-MCP\\apktool_mcp_server.py"
      ],
      "transportType": "stdio"
    }
  }
}
```

> 📝 **Notes**:
Please adjust according to your actual file path and configuration(adjust according to your system).
Make sure to fill in your actual `MOBSF_API_KEY` in the configuration.


## 🛠️ API

### JEB MCP

Architecture based on https://github.com/flankerhqd/jebmcp

**✨ Main API Functions:**

| API | Description |
|-----|-------------|
| `ping()` | Check if the JEB MCP server is alive. |
| `get_manifest(filepath)` | Get the AndroidManifest.xml content from the APK. |
| `get_apk_permissions(filepath)` | Extract all permissions declared in the APK's AndroidManifest.xml. |
| `get_apk_components(filepath)` | Extract all four major Android components (activities, services, receivers, providers) and their attributes from the manifest. |
| `get_method_decompiled_code(filepath, method_signature)` | Get the decompiled code of a specific method by its fully-qualified signature. |
| `get_class_decompiled_code(filepath, class_signature)` | Get the decompiled code of a specific class by its fully-qualified signature. |
| `get_method_callers(filepath, method_signature)` | List all callers of a given method. |
| `get_method_overrides(filepath, method_signature)` | List all overrides of a given method. |
| `get_apk_info(filepath)` | Get basic APK info such as package name, version, and main activity. |
| `get_intent_filters(filepath)` | Extract all intent-filters (actions, categories, data) for activities, services, and receivers. |
| `get_exported_components(filepath)` | List all exported components (explicit or implicit) and their attributes. |
| `list_broadcast_receivers(filepath)` | List all broadcast receivers and their intent-filters. |

**Parameter notes:**
- `filepath` should be the absolute path to the APK file.
- `method_signature` and `class_signature` use Java-style internal addresses, e.g. `Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V` for methods, `Lcom/abc/Foo;` for classes.

---

### JADX MCP

Architecture based on https://github.com/mobilehackinglab/jadx-mcp-plugin

**✨ Main API Functions:**

| API | Description |
|-----|-------------|
| `list_all_classes(limit, offset)` | Returns a paginated list of all class names in the APK. Parameters: `limit` (max results, default 250), `offset` (start index, default 0). |
| `search_class_by_name(query)` | Search for class names containing the given keyword (case-insensitive). Parameter: `query` (string). |
| `get_class_source(class_name)` | Returns the full decompiled source code of a given class. Parameter: `class_name` (fully qualified class name, e.g., `com.example.MyClass`). |
| `search_method_by_name(method_name)` | Search for all methods matching the provided name. Returns class and method pairs as strings. Parameter: `method_name` (string). |
| `get_methods_of_class(class_name)` | Returns all method names declared in the specified class. Parameter: `class_name` (fully qualified class name). |
| `get_fields_of_class(class_name)` | Returns all field names declared in the specified class. Parameter: `class_name` (fully qualified class name). |
| `get_method_code(class_name, method_name)` | Returns only the source code block of a specific method within a class. Parameters: `class_name` (fully qualified class name), `method_name` (string). |
| `get_method_signature(class_name, method_name)` | Returns the full signature of a method, including return type and parameters. Parameters: `class_name` (fully qualified class name), `method_name` (string). |
| `get_field_details(class_name, field_name)` | Returns detailed information about a field, including its type and modifiers. Parameters: `class_name` (fully qualified class name), `field_name` (string). |
| `search_method_by_return_type(return_type)` | Search for methods by their return type. Parameter: `return_type` (string). |
| `get_class_hierarchy(class_name)` | Returns the inheritance hierarchy of a class, including its parent classes and interfaces. Parameter: `class_name` (fully qualified class name). |
| `get_method_calls(class_name, method_name)` | Returns all method calls made within a specific method. Parameters: `class_name` (fully qualified class name), `method_name` (string). |
| `get_class_references(class_name)` | Returns all references to a specific class in the codebase. Parameter: `class_name` (fully qualified class name). |
| `get_method_annotations(class_name, method_name)` | Returns all annotations applied to a specific method. Parameters: `class_name` (fully qualified class name), `method_name` (string). |
| `get_tools_resource()` | Returns the list of all available tools and their descriptions from the plugin. |

**Parameter notes:**
- `class_name` should be the fully qualified class name, e.g. `com.example.MyClass`.
- `method_name` is the method's name as shown in the decompiled code.
- `limit` and `offset` are for pagination when listing classes.
- `query`: search keyword, used to search for class names or method names containing the keyword.
- `return_type`: the return type of the method, used to search for methods by return type.
- `field_name`: the name of the field, used to obtain detailed information about the field.
---

### APKTool MCP

Architecture based on https://github.com/zinja-coder/apktool-mcp-server (Apache 2.0 License)

**✨ Main API Functions:**

| API | Description |
|-----|-------------|
| `decode_apk(apk_path, force, no_res, no_src)` | Decompile an APK file, extracting resources and smali code. Parameters: `apk_path` (APK file path), `force` (force overwrite), `no_res` (skip resources), `no_src` (skip sources). |
| `build_apk(project_dir, output_apk, debug, force_all)` | Rebuild an APK from a decoded project. Parameters: `project_dir` (project path), `output_apk` (output path), `debug` (include debug info), `force_all` (force rebuild all). |
| `clean_project(project_dir, backup)` | Clean a project directory to prepare for rebuilding. Parameters: `project_dir` (project path), `backup` (create backup before cleaning). |
| `get_manifest(project_dir)` | Get the AndroidManifest.xml content from a decoded project. Parameter: `project_dir` (project path). |
| `find_leak_manifest(project_dir)` | Find exported components without permission restrictions in the manifest. Parameter: `project_dir`. |
| `find_leak_components_source(project_dir, source_dirs)` | Find exported components without permissions and locate their source code. Parameters: `project_dir`, `source_dirs` (list of source directories). |
| `list_smali_directories(project_dir)` | List all smali directories in a project. Parameter: `project_dir`. |
| `list_smali_files(project_dir, smali_dir, package_prefix)` | List smali files in a specific directory. Parameters: `project_dir`, `smali_dir` (default: "smali"), `package_prefix` (optional filter). |
| `get_smali_file(project_dir, class_name)` | Get content of a specific smali file. Parameters: `project_dir`, `class_name` (fully qualified class name). |
| `modify_smali_file(project_dir, class_name, new_content, create_backup)` | Modify smali file content. Parameters: `project_dir`, `class_name`, `new_content`, `create_backup` (default: True). |
| `list_resources(project_dir, resource_type)` | List resources in project. Parameters: `project_dir`, `resource_type` (optional, e.g. "layout", "drawable"). |
| `get_resource_file(project_dir, resource_type, resource_name)` | Get resource file content. Parameters: `project_dir`, `resource_type`, `resource_name`. |
| `modify_resource_file(project_dir, resource_type, resource_name, new_content, create_backup)` | Modify resource file content. Parameters: `project_dir`, `resource_type`, `resource_name`, `new_content`, `create_backup` (default: True). |
| `search_in_files(project_dir, search_pattern, file_extensions, max_results)` | Search in project files. Parameters: `project_dir`, `search_pattern`, `file_extensions` (default: [".smali", ".xml"]), `max_results` (default: 100). |
| `get_apktool_yml(project_dir)` | Get apktool.yml information from a decoded project. Parameter: `project_dir`. |

**Parameter notes:**
- `project_dir`: Path to the APKTool project directory
- `apk_path`: Path to the APK file
- `class_name`: Fully qualified class name (e.g. "com.example.MyClass")
- `resource_type`: Resource directory name (e.g. "layout", "drawable", "values")
- `create_backup`: Whether to create backup before modifications (default: True)
- `file_extensions`: List of file extensions to search in (default: [".smali", ".xml"])

---

### MobSF MCP

**✨ Main API Functions:**

| API | Description |
|-----|-------------|
| `uploadFile(file)` | Upload a mobile application file (APK, IPA, or APPX) to MobSF for security analysis. |
| `getScanLogs(hash)` | Retrieve detailed scan logs for a previously analyzed mobile application. |
| `getJsonReport(hash)` | Generate and retrieve a comprehensive security analysis report in JSON format. |
| `getJsonReportSection(hash, section)` | Get a specific section of the JSON report. |
| `getJsonReportSections(hash)` | Get all available section names in the JSON report. |
| `getRecentScans(page, pageSize)` | Retrieve a list of recently performed security scans. |
| `searchScanResult(query)` | Search scan results by hash, app name, package name, or file name. |
| `deleteScan(hash)` | Delete scan results for a specific analysis. |
| `getScorecard(hash)` | Get MobSF Application Security Scorecard. |
| `generatePdfReport(hash)` | Generate PDF security report (returns base64 encoded PDF). |
| `viewSource(hash, file, type)` | View source files from the analyzed application. |
| `getScanTasks()` | Get scan tasks queue (requires async scan queue enabled). |
| `compareApps(hash1, hash2)` | Compare security analysis results between two applications. |
| `suppressByRule(hash, type, rule)` | Suppress findings by rule ID. |
| `suppressByFiles(hash, type, rule)` | Suppress findings by files. |
| `listSuppressions(hash)` | View all suppressions for a scan. |
| `deleteSuppression(hash, type, rule, kind)` | Delete specific suppressions. |
| `listAllHashes(page, pageSize)` | Get all report MD5 hash values. |

**📊 Report Section APIs:**

MobSF provides detailed section-specific APIs for accessing different parts of the analysis report. Each section can be accessed using `getJsonSection_{section}(hash)`:

| Section Category | Available Sections |
|-----------------|-------------------|
| Basic Info | `version`, `title`, `file_name`, `app_name`, `app_type`, `size`, `md5`, `sha1`, `sha256` |
| Application Info | `package_name`, `main_activity`, `version_name`, `version_code` |
| Components | `exported_activities`, `browsable_activities`, `activities`, `receivers`, `providers`, `services` |
| SDK Info | `target_sdk`, `max_sdk`, `min_sdk`, `libraries` |
| Security Analysis | `permissions`, `malware_permissions`, `certificate_analysis`, `manifest_analysis`, `network_security`, `binary_analysis` |
| Code Analysis | `file_analysis`, `android_api`, `code_analysis`, `niap_analysis`, `permission_mapping` |
| Content Analysis | `urls`, `domains`, `emails`, `strings`, `firebase_urls`, `secrets` |
| Additional Info | `exported_count`, `apkid`, `behaviour`, `trackers`, `playstore_details`, `sbom` |
| Security Metrics | `average_cvss`, `appsec`, `virus_total` |
| System Info | `base_url`, `dwd_dir`, `host_os` |

**Parameter notes:**
- `file`: Path to the mobile application file (APK/IPA/APPX)
- `hash`: MD5 hash of the analyzed application
- `section`: Name of the report section to retrieve
- `page`: Page number for paginated results
- `pageSize`: Number of items per page
- `type`: File type (apk/ipa/studio/eclipse/ios)
- `rule`: Rule ID for suppression management
- `kind`: Suppression kind (rule/file)

---

### FlowDroid MCP

**✨ Main API Functions:**

| API | Description |
|-----|-------------|
| `run_flowdroid_analysis(apk_path, output_dir)` | Run FlowDroid taint analysis on an APK file. Parameters: `apk_path` (APK file path), `output_dir` (optional output directory). |
| `get_flowdroid_sources(analysis_dir)` | Extract taint sources from FlowDroid analysis results. Parameter: `analysis_dir` (analysis output directory). |
| `get_flowdroid_sinks(analysis_dir)` | Extract taint sinks from FlowDroid analysis results. Parameter: `analysis_dir` (analysis output directory). |
| `clean_flowdroid_workspace()` | Clean the FlowDroid workspace directory to prepare for new analysis. |

**Parameter notes:**
- `apk_path`: Path to the APK file to analyze
- `output_dir`: Optional output directory (defaults to workspace/apk_name)
- `analysis_dir`: Path to FlowDroid analysis output directory

---

## 🧠 Multi-expert decision model

This project uses the "multi-expert decision" model to conduct a comprehensive analysis of APK security. This model draws on the idea of ​​independent judgment and collective decision-making of multiple experts, and combines the MCP interface of 5 mainstream reverse analysis tools (JEB, JADX, APKTool, FlowDroid, MobSF), which greatly improves the comprehensiveness of vulnerability discovery and the credibility of the results.

### Analysis process overview

1. **Multiple experts answer independently**
- 5 reverse analysis tools (MCP) independently perform static analysis on the same APK and automatically generate their own vulnerability reports.
- Each tool, as an "expert", independently discovers potential security issues from different perspectives and technical details.

2. **Big model frequency statistics and ranking**
- Use the big model to merge, deduplicate and content analyze the vulnerabilities output by all tools, count the frequency of each vulnerability in the 5 tool reports, and record its source.
- Rank all vulnerabilities by frequency of occurrence. The higher the frequency, the more reliable it is.

3. **Local priority screening and diversion**
- The top 60% of high-frequency vulnerabilities (i.e., vulnerabilities that appear more frequently and are more reliable in the five tools) are automatically retained locally.
- The bottom 40% of vulnerabilities are divided into two categories:
  - **No MobSF source**: that is, vulnerabilities that are only discovered by other reverse tools are all retained.
  - **With MobSF source**: that is, low-frequency vulnerabilities that only appear in MobSF reports are handed over to the big model for further evaluation of their danger, and only high-risk vulnerabilities are retained.

4. **Final comprehensive integration**
All high-priority vulnerabilities, unique vulnerabilities, and MobSF vulnerabilities that are evaluated as high-risk by the big model are integrated locally in the third step to generate the final comprehensive vulnerability analysis report.

### CrossValidation_APKAnalysis MCP

**✨ Main API Functions:**

| API | Description |
|-----|-------------|
| `analyze_with_jeb/jadx/apktool/flowdroid/mobsf(apk_path)` | Analyze APK independently using the JEB/JADX/APKTool/FlowDroid/MobSF MCP tool and generate a standardized vulnerability report. Parameter: `apk_path` (APK file path). |
| `combine_analysis_results(report_paths)` | Merge the reports from all 5 tools, count the frequency and source of each vulnerability, and sort by component weight to generate a preliminary comprehensive report. Parameter: `report_paths` (list of report file paths). |
| `split_vulnerabilities_by_priority(combined_report_path)` | Divide vulnerabilities into three categories based on frequency: high priority (top 60%), low priority without MobSF source, and low priority with only MobSF source, and save them separately. Parameter: `combined_report_path` (path to the combined report). |
| `assess_vulnerability_risk(mobsf_low_priority_path)` | For low-priority vulnerabilities only from MobSF, call the large model for risk assessment and keep only high-risk vulnerabilities. Parameter: `mobsf_low_priority_path` (path to MobSF-only low-priority vulnerabilities). |
| `integrate_priority_reports(high_priority_path, unique_low_priority_path, high_risk_mobsf_path)` | Integrate high-priority, unique low-priority, and high-risk MobSF vulnerabilities to generate the final comprehensive analysis report. Parameters: `high_priority_path`, `unique_low_priority_path`, `high_risk_mobsf_path` (paths to each report). |

**Parameter notes:**
- `apk_path`: Absolute path to the APK file to be analyzed.
- `report_paths`: List of standardized report file paths from each tool.
- `combined_report_path`: Path to the merged preliminary comprehensive report.
- `mobsf_low_priority_path`: Path to low-priority vulnerabilities only from MobSF.
- `high_priority_path`, `unique_low_priority_path`, `high_risk_mobsf_path`: Paths to different priority vulnerability reports.

### 🖥️ VSCode Cline Extension Configuration

To use this project with the [cline](https://marketplace.visualstudio.com/items?itemName=cline-tools.cline) extension in VSCode, add the following configuration to your cline configuration file:

```json
{
  "mcpServers": {
   "apk_analysis": {
      "disabled": false,
      "timeout": 60,
      "command": "myenv\\Scripts\\python.exe",
      "args": [
        "CrossValidation_APKAnalysis.py"
      ],
      "transportType": "stdio"
    }
  }
}
```

Through the above process, the project has achieved multi-tool, multi-perspective vulnerability discovery and automated decision-making, greatly improving the comprehensiveness, accuracy and practical value of the analysis results.

---

## 📜 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---
## 🙏 Acknowledgments

This project builds upon and integrates several outstanding open-source tools and projects.

Special thanks to:
- The developers and maintainers of all integrated tools
- The open source community for their continuous contributions
- All contributors who have helped improve this project
---
## ⚠️ Disclaimer and Legal Notice

This tool suite is designed for security researchers, penetration testers, and developers for legitimate security testing and analysis purposes only. Users must:

1. Only analyze applications they own or have explicit permission to test
2. Comply with all applicable laws and regulations
3. Respect intellectual property rights and terms of service
4. Use the tools responsibly and ethically

Users must ensure their use of this tool complies with:
- Local and international laws
- Software license agreements
- Terms of service of analyzed applications
- Data protection and privacy regulations

---

## 🤝 Contributing

We warmly welcome contributions from the community! Whether you're fixing bugs, improving documentation, adding new features, or suggesting enhancements, your help is appreciated.

- 🐛 Report bugs and issues
- 💡 Propose new features or improvements
- 📝 Improve documentation
- 🔍 Review code and pull requests
- 💻 Submit pull requests 

We strive to make this project better together. Your contributions help make this tool more powerful and useful for the entire security research community.

