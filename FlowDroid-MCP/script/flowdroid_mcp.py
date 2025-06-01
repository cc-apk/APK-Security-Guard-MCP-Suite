
import logging
import subprocess
import os
import shutil
from typing import List, Dict, Optional, Union
from dotenv import load_dotenv
from fastmcp import FastMCP
import json
import sys
# 加载 .env 文件中的环境变量
logger = logging.getLogger(__name__)
load_dotenv()

# 获取环境变量
FLOWDROID_WORKSPACE = os.getenv("FLOWDROID_WORKSPACE", "flowdroid_workspace")
FLOWDROID_JAR_PATH = os.getenv("FLOWDROID_JAR_PATH", "FlowDroid.jar")
JAVA_HOME = os.getenv("JAVA_HOME")  # 如果需要特定 JAVA_HOME 设置

# 确保工作空间目录存在
os.makedirs(FLOWDROID_WORKSPACE, exist_ok=True)
logger.info(f"Initialized FLOWDROID_WORKSPACE at: {FLOWDROID_WORKSPACE}")

# 设置日志配置
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 初始化 MCP 对象
mcp = FastMCP("flowdroid-mcp-server")
logger.info("Initialized FastMCP server with name 'flowdroid-mcp-server'")

def run_flowdroid_command(command: List[str], timeout: int = 300) -> Dict[str, Union[str, int, bool]]:
    """
    Run a FlowDroid command and handle the result.
    
    Args:
        command: The command to execute
        timeout: Maximum execution time in seconds
        
    Returns:
        Dictionary with command execution results
    """
    logger.debug(f"Preparing to run command: {' '.join(command)}")
    try:
        logger.info(f"Running FlowDroid command: {' '.join(command)}")
        
        # 在Windows上显示完整命令路径（如果JAVA_HOME设置）
        if JAVA_HOME:
            java_path = os.path.join(JAVA_HOME, "bin", "java.exe")
            command[0] = java_path if os.path.exists(java_path) else command[0]
            logger.debug(f"Using Java path: {command[0]}")
        
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=timeout
        )
        
        logger.info(f"FlowDroid command completed successfully with return code {result.returncode}")
        logger.debug(f"stdout: {result.stdout}")
        logger.debug(f"stderr: {result.stderr}")
        
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.CalledProcessError as e:
        logger.error(f"FlowDroid command failed with return code {e.returncode}: {e.stderr}")
        logger.debug(f"Command that failed: {' '.join(command)}")
        return {
            "success": False,
            "stdout": e.stdout,
            "stderr": e.stderr,
            "returncode": e.returncode,
            "error": f"Command failed with return code {e.returncode}"
        }
    except subprocess.TimeoutExpired as e:
        logger.error(f"FlowDroid command timed out after {timeout} seconds")
        logger.debug(f"Timeout occurred for command: {' '.join(command)}")
        return {
            "success": False,
            "error": f"Command timed out after {timeout} seconds"
        }
    except Exception as e:
        logger.error(f"Error running FlowDroid command: {str(e)}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool(name="run_flowdroid_analysis", description="Run FlowDroid taint analysis on an APK")
def run_flowdroid_analysis(apk_path: str, output_dir: Optional[str] = None) -> Dict:
    """
    Run FlowDroid taint analysis on an APK file.
    
    Args:
        apk_path: Path to the APK file
        output_dir: Optional output directory (defaults to workspace/apk_name)
        
    Returns:
        Dictionary with analysis results or error
    """
    logger.info(f"Starting FlowDroid analysis for APK: {apk_path}")
    
    if not os.path.exists(apk_path):
        error_msg = f"APK file not found: {apk_path}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

    # 设置输出目录
    apk_name = os.path.basename(apk_path).rsplit('.', 1)[0]
    output_dir = os.path.join(FLOWDROID_WORKSPACE, apk_name)
    
    # 调试日志：打印环境变量和完整路径
    logger.debug(f"FLOWDROID_WORKSPACE: {FLOWDROID_WORKSPACE}")
    logger.debug(f"Full output path: {os.path.abspath(output_dir)}")
    
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Using output directory: {os.path.abspath(output_dir)}")

    # 构建 FlowDroid 命令
    command = [
        "java", 
        "-jar", 
        FLOWDROID_JAR_PATH,  # 确保路径正确
        "-a", apk_path,
        "-o", output_dir,
        "-p", "Android\\Sdk\\platforms",  # 必须指定 platforms 目录
        "-s", "FlowDroid-MCP\\script\\SourcesAndSinks.txt",
            # 必须指定源/汇文件
    ]
    
    logger.debug(f"Constructed FlowDroid command: {' '.join(command)}")
    
    # 运行命令
    result = run_flowdroid_command(command)

    if result["success"]:
        logger.info(f"FlowDroid analysis completed successfully. Results saved in {output_dir}")
        return {
            "success": True,
            "output_dir": output_dir,
            "message": f"FlowDroid analysis completed. Results saved in {output_dir}",
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", "")
        }
    else:
        error_msg = f"FlowDroid analysis failed: {result.get('error', 'Unknown error')}"
        logger.error(error_msg)
        if "stderr" in result:
            logger.error(f"Error details: {result['stderr']}")
        return {
            "success": False,
            "error": error_msg,
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "returncode": result.get("returncode", -1)
        }

@mcp.tool(name="get_flowdroid_sources", description="Get taint sources from FlowDroid analysis")
def get_flowdroid_sources(analysis_dir: str) -> Dict:
    """
    Extract taint sources from FlowDroid analysis results.
    
    Args:
        analysis_dir: Path to FlowDroid analysis directory
        
    Returns:
        Dictionary with list of taint sources or error
    """
    logger.info(f"Extracting taint sources from analysis directory: {analysis_dir}")
    
    if not os.path.exists(analysis_dir):
        error_msg = f"Analysis directory not found: {analysis_dir}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

    results_path = os.path.join(analysis_dir, "sieve.xml")

    if not os.path.exists(results_path):
        error_msg = f"FlowDroid results file not found: {results_path}"
        logger.error(error_msg)
        return {
            "success": False,
            "error": error_msg
        }

    try:
        with open(results_path, 'r', encoding='utf-8') as f:
            content = f.read()
        logger.debug(f"Successfully read FlowDroid results file: {results_path}")

        # 解析结果文件获取污点源（这里需要根据实际 FlowDroid 输出格式调整）
        sources = []
        for line in content.split('\n'):
            if "Taint Source:" in line:
                source = line.split("Taint Source:")[1].strip()
                sources.append(source)
                logger.debug(f"Found taint source: {source}")

        logger.info(f"Found {len(sources)} taint sources in analysis results")
        return {
            "success": True,
            "sources": sources,
            "count": len(sources)
        }
    except Exception as e:
        logger.error(f"Error parsing FlowDroid results: {str(e)}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Failed to parse FlowDroid results: {str(e)}"
        }

@mcp.tool(name="get_flowdroid_sinks", description="Get taint sinks from FlowDroid analysis")
def get_flowdroid_sinks(analysis_dir: str) -> Dict:
    """
    Extract taint sinks from FlowDroid analysis results.
    
    Args:
        analysis_dir: Path to FlowDroid analysis directory
        
    Returns:
        Dictionary with list of taint sinks or error
    """
    logger.info(f"Extracting taint sinks from analysis directory: {analysis_dir}")
    
    if not os.path.exists(analysis_dir):
        error_msg = f"Analysis directory not found: {analysis_dir}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

    results_path = os.path.join(analysis_dir, "sieve.xml")

    if not os.path.exists(results_path):
        error_msg = f"FlowDroid results file not found: {results_path}"
        logger.error(error_msg)
        return {
            "success": False,
            "error": error_msg
        }

    try:
        with open(results_path, 'r', encoding='utf-8') as f:
            content = f.read()
        logger.debug(f"Successfully read FlowDroid results file: {results_path}")

        # 解析结果文件获取污点汇（这里需要根据实际 FlowDroid 输出格式调整）
        sinks = []
        for line in content.split('\n'):
            if "Taint Sink:" in line:
                sink = line.split("Taint Sink:")[1].strip()
                sinks.append(sink)
                logger.debug(f"Found taint sink: {sink}")

        logger.info(f"Found {len(sinks)} taint sinks in analysis results")
        return {
            "success": True,
            "sinks": sinks,
            "count": len(sinks)
        }
    except Exception as e:
        logger.error(f"Error parsing FlowDroid results: {str(e)}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Failed to parse FlowDroid results: {str(e)}"
        }

@mcp.tool(name="clean_flowdroid_workspace", description="Clean FlowDroid workspace directory")
def clean_flowdroid_workspace() -> Dict:
    """
    Clean the FlowDroid workspace directory.
    
    Returns:
        Dictionary with operation results
    """
    logger.info(f"Cleaning FlowDroid workspace directory: {FLOWDROID_WORKSPACE}")
    
    try:
        # 删除工作空间目录
        if os.path.exists(FLOWDROID_WORKSPACE):
            shutil.rmtree(FLOWDROID_WORKSPACE)
            logger.info(f"Successfully removed old workspace directory: {FLOWDROID_WORKSPACE}")
        
        # 重新创建
        os.makedirs(FLOWDROID_WORKSPACE, exist_ok=True)
        logger.info(f"Successfully recreated workspace directory: {FLOWDROID_WORKSPACE}")
        
        return {
            "success": True,
            "message": f"FlowDroid workspace cleaned. Directory: {FLOWDROID_WORKSPACE}"
        }
    except Exception as e:
        logger.error(f"Error cleaning FlowDroid workspace: {str(e)}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Failed to clean FlowDroid workspace: {str(e)}"
        }

if __name__ == "__main__":
    try:
        mcp.run()
      
    except Exception as e:
        logger.error(f"FastMCP service failed to start: {e}", exc_info=True)
        sys.exit(1)
