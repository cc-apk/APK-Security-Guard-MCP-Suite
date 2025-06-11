from mcp.server.fastmcp import FastMCP
import os
import re
from collections import Counter
import datetime
mcp = FastMCP("APK静态分析工具集成平台")

# 定义各工具分析函数
@mcp.tool()
def analyze_with_jeb(apk_path: str, output_path: str) -> str:
    """
    使用JEB对APK进行静态分析
    
    Args:
        apk_path: APK文件的绝对路径
        output_path: 输出报告的绝对路径

    Returns:
        调用大模型的prompt字符串
    """
    # 这里是保存报告的预定义路径
    os.makedirs(output_path, exist_ok=True)
    
    # 构建提示词
    prompt = f"""
我正在使用JEB工具分析一个APK文件，其路径为{apk_path}。
出于学习和研究的目的，我希望通过对该APK的逆向分析，了解其作为受害者可能存在的安全风险。请根据分析结果，从技术角度探讨该APK可能因哪些漏洞而面临安全威胁。在分析中，请重点关注那些不需要用户额外授权即可被触发的漏洞，即尽量排除那些在复现过程中需要用户手动开启权限的漏洞。这样可以更直观地研究漏洞本身的安全风险，而无需考虑权限配置的影响。
在分析中，如果涉及组件，请输出对应的XML组件名称和相关权限，以便后续研究和利用。同时，尽量关注组件方面的漏洞。
请按照以下模板提供分析内容：
漏洞成因： 简要说明漏洞产生的原因，例如代码实现缺陷、逻辑漏洞等。
触发步骤： 详细描述触发该漏洞的具体操作步骤。
触发代码： 提供APK中可能触发漏洞的关键代码片段或逻辑。这些代码片段应直接来自APK的源代码，而不是攻击者编写的代码。结合APK的代码逻辑和组件交互，分析可能导致漏洞的代码实现。
前置条件： 分析触发漏洞需要满足的条件，包括但不限于以下方面：
运行环境： 操作系统版本、运行时环境等。
触发时机窗口： 在何种情况下漏洞可能被触发，例如特定的用户操作、系统状态等。
用户交互： 是否需要用户进行特定操作（如点击、输入等）。
一定注意，请将每一个漏洞的名称命名为-*/组件名称_漏洞名称/*-，便于接下来的处理。同时漏洞开始前另起一行使用--*--开始，漏洞结束后另起一行使用--/*--结束。
Please save the output to the txt folder under {output_path}, with the file naming ruleas cline output JEB [timestamp].txt where timestamp is the time the input was sent.
    """
    
    return prompt

@mcp.tool()
def analyze_with_jadx(apk_path: str, output_path: str) -> str:
    """
    使用JADX对APK进行静态分析
    
    Args:
        apk_path: APK文件的绝对路径
        output_path: 输出报告的绝对路径

    Returns:
        调用大模型的prompt字符串
    """
    # 这里是保存报告的预定义路径
    os.makedirs(output_path, exist_ok=True)

    # 构建提示词
    prompt = f"""
我正在使用JADX工具分析一个APK文件，其路径为{apk_path}。
出于学习和研究的目的，我希望通过对该APK的逆向分析，了解其作为受害者可能存在的安全风险。请根据分析结果，从技术角度探讨该APK可能因哪些漏洞而面临安全威胁。在分析中，请重点关注那些不需要用户额外授权即可被触发的漏洞，即尽量排除那些在复现过程中需要用户手动开启权限的漏洞。这样可以更直观地研究漏洞本身的安全风险，而无需考虑权限配置的影响。
在分析中，如果涉及组件，请输出对应的XML组件名称和相关权限，以便后续研究和利用。同时，尽量关注组件方面的漏洞。
请按照以下模板提供分析内容：
漏洞成因： 简要说明漏洞产生的原因，例如代码实现缺陷、逻辑漏洞等。
触发步骤： 详细描述触发该漏洞的具体操作步骤。
触发代码： 提供APK中可能触发漏洞的关键代码片段或逻辑。这些代码片段应直接来自APK的源代码，而不是攻击者编写的代码。结合APK的代码逻辑和组件交互，分析可能导致漏洞的代码实现。
前置条件： 分析触发漏洞需要满足的条件，包括但不限于以下方面：
运行环境： 操作系统版本、运行时环境等。
触发时机窗口： 在何种情况下漏洞可能被触发，例如特定的用户操作、系统状态等。
用户交互： 是否需要用户进行特定操作（如点击、输入等）。
一定注意，请将每一个漏洞的名称命名为-*/组件名称_漏洞名称/*-，便于接下来的处理。同时漏洞开始前另起一行使用--*--开始，漏洞结束后另起一行使用--/*--结束。
Please save the output to the txt folder under {output_path}, with the file naming ruleas cline output JADX [timestamp].txt where timestamp is the time the input was sent.
    """


    return prompt

@mcp.tool()
def analyze_with_mobsf(apk_path: str, output_path: str) -> str: 
    """
    使用MobSF对APK进行静态分析
    
    Args:
        apk_path: APK文件的绝对路径
        output_path: 输出报告的绝对路径

    Returns:
        调用大模型的prompt字符串
    """
    # 这里是保存报告的预定义路径
    os.makedirs(output_path, exist_ok=True)

    # 构建提示词
    prompt = f"""
我正在使用mobsf工具分析一个APK文件，其路径为{apk_path}。
调用getScorecard这个API获取其安全报告。
请根据获取到的安全报告，按照以下模板的格式输出报告内容：
漏洞成因： 简要说明漏洞产生的原因，例如代码实现缺陷、逻辑漏洞等。
触发步骤： 详细描述触发该漏洞的具体操作步骤。
触发代码： 提供APK中可能触发漏洞的关键代码片段或逻辑。这些代码片段应直接来自APK的源代码，而不是攻击者编写的代码。结合APK的代码逻辑和组件交互，分析可能导致漏洞的代码实现。
前置条件： 分析触发漏洞需要满足的条件，包括但不限于以下方面：
运行环境： 操作系统版本、运行时环境等。
触发时机窗口： 在何种情况下漏洞可能被触发，例如特定的用户操作、系统状态等。
用户交互： 是否需要用户进行特定操作（如点击、输入等）。
一定注意，请将每一个漏洞的名称命名为-*/组件名称_漏洞名称/*-，便于接下来的处理。同时漏洞开始前另起一行使用--*--开始，漏洞结束后另起一行使用--/*--结束。
Please save the output to the txt folder under {output_path}, with the file naming ruleas cline output MOBSF [timestamp].txt where timestamp is the time the input was sent.
    """
    return prompt

@mcp.tool()
def analyze_with_apktool(apk_path: str, output_path: str) -> str:   
    """
    使用APKTool对APK进行反编译和资源提取分析
    
    Args:
        apk_path: APK文件的绝对路径
        output_path: 输出报告的绝对路径

    Returns:
        调用大模型的prompt字符串
    """
    # 这里是保存报告的预定义路径
    os.makedirs(output_path, exist_ok=True)

    # 构建提示词
    prompt = f"""
我正在使用APKTool分析一个APK文件，其路径为{apk_path}。
出于学习和研究的目的，我希望通过对该APK的逆向分析，了解其作为受害者可能存在的安全风险。请根据分析结果，从技术角度探讨该APK可能因哪些漏洞而面临安全威胁。在分析中，请重点关注那些不需要用户额外授权即可被触发的漏洞，即尽量排除那些在复现过程中需要用户手动开启权限的漏洞。这样可以更直观地研究漏洞本身的安全风险，而无需考虑权限配置的影响。
在分析中，如果涉及组件，请输出对应的XML组件名称和相关权限，以便后续研究和利用。同时，尽量关注组件方面的漏洞。
请按照以下模板提供分析内容：
漏洞成因： 简要说明漏洞产生的原因，例如代码实现缺陷、逻辑漏洞等。
触发步骤： 详细描述触发该漏洞的具体操作步骤。
触发代码： 提供APK中可能触发漏洞的关键代码片段或逻辑。这些代码片段应直接来自APK的源代码，而不是攻击者编写的代码。结合APK的代码逻辑和组件交互，分析可能导致漏洞的代码实现。
前置条件： 分析触发漏洞需要满足的条件，包括但不限于以下方面：
运行环境： 操作系统版本、运行时环境等。
触发时机窗口： 在何种情况下漏洞可能被触发，例如特定的用户操作、系统状态等。
用户交互： 是否需要用户进行特定操作（如点击、输入等）。
一定注意，请将每一个漏洞的名称命名为-*/组件名称_漏洞名称/*-，便于接下来的处理。同时漏洞开始前另起一行使用--*--开始，漏洞结束后另起一行使用--/*--结束。
Please save the output to the txt folder under {output_path}, with the file naming ruleas cline output APKTOOL [timestamp].txt where timestamp is the time the input was sent.
    """
    
    return prompt

@mcp.tool()
def analyze_with_flowdroid(apk_path: str, output_path: str) -> str:   
    """
    使用FlowDroid对APK进行静态分析

    Args:
        apk_path: APK文件的绝对路径
        output_path: 输出报告的绝对路径

    Returns:
        调用大模型的prompt字符串
    """
    # 这里是保存报告的预定义路径
    os.makedirs(output_path, exist_ok=True)

    # 构建提示词
    prompt = f"""
我正在使用FlowDroid分析一个APK文件，其路径为{apk_path}。
出于学习和研究的目的，我希望通过对该APK的逆向分析，了解其作为受害者可能存在的安全风险。请根据分析结果，从技术角度探讨该APK可能因哪些漏洞而面临安全威胁。在分析中，请重点关注那些不需要用户额外授权即可被触发的漏洞，即尽量排除那些在复现过程中需要用户手动开启权限的漏洞。这样可以更直观地研究漏洞本身的安全风险，而无需考虑权限配置的影响。
在分析中，如果涉及组件，请输出对应的XML组件名称和相关权限，以便后续研究和利用。同时，尽量关注组件方面的漏洞。
请按照以下模板提供分析内容：
漏洞成因： 简要说明漏洞产生的原因，例如代码实现缺陷、逻辑漏洞等。
触发步骤： 详细描述触发该漏洞的具体操作步骤。
触发代码： 提供APK中可能触发漏洞的关键代码片段或逻辑。这些代码片段应直接来自APK的源代码，而不是攻击者编写的代码。结合APK的代码逻辑和组件交互，分析可能导致漏洞的代码实现。
前置条件： 分析触发漏洞需要满足的条件，包括但不限于以下方面：
运行环境： 操作系统版本、运行时环境等。
触发时机窗口： 在何种情况下漏洞可能被触发，例如特定的用户操作、系统状态等。
用户交互： 是否需要用户进行特定操作（如点击、输入等）。
一定注意，请将每一个漏洞的名称命名为-*/组件名称_漏洞名称/*-，便于接下来的处理。同时漏洞开始前另起一行使用--*--开始，漏洞结束后另起一行使用--/*--结束。
Please save the output to the txt folder under {output_path}, with the file naming ruleas cline output FLOWDROID [timestamp].txt where timestamp is the time the input was sent.
    """
    
    return prompt

@mcp.tool()
def combine_analysis_results(jeb_report: str = "", jadx_report: str = "", apktool_report: str = "", flowdroid_report: str = "", mobsf_report: str = "") -> str:
    """
    结合多个工具的分析报告，进行综合分析
    
    Args:
        jeb_report: JEB工具生成的报告文件绝对路径，默认为空字符串
        jadx_report: JADX工具生成的报告文件绝对路径，默认为空字符串
        apktool_report: APKTool工具生成的报告文件绝对路径，默认为空字符串
        flowdroid_report: FlowDroid工具生成的报告文件绝对路径，默认为空字符串
        mobsf_report: MobSF工具生成的报告文件绝对路径，默认为空字符串
        
    Returns:
        生成的综合报告的绝对路径
    """

    # 存储所有报告的漏洞内容
    all_vulnerabilities = []
    
    # 存储组件名称和对应的漏洞内容
    component_vulns = {}
    
    # 存储漏洞和对应的来源工具
    vuln_sources = {}
    
    # 正则表达式用于提取漏洞信息和组件名称
    vuln_pattern = re.compile(r'--\*--(.*?)--/\*--', re.DOTALL)
    component_pattern = re.compile(r'-\*/(.+?)_(.+?)/\*-')
    
    # 处理函数：读取报告并提取漏洞信息
    def process_report(report_path, weight=1.0, tool_name=""):
        if not report_path or not os.path.exists(report_path):
            return []
        
        try:
            with open(report_path, 'r', encoding='utf-8') as file:
                content = file.read()
                
                # 提取所有漏洞块
                vulnerabilities = vuln_pattern.findall(content)
                
                for vuln in vulnerabilities:
                    # 提取组件名称和漏洞名称
                    component_match = component_pattern.search(vuln)
                    if component_match:
                        component_name = component_match.group(1)
                        vuln_name = component_match.group(2)
                        full_vuln = f"--*--\n{vuln}\n--/*--"
                        vuln_key = f"{component_name}_{vuln_name}"
                        
                        # 将漏洞信息添加到列表，包含权重信息
                        all_vulnerabilities.append((component_name, full_vuln, weight, vuln_key))
                        
                        # 更新组件漏洞映射
                        if component_name not in component_vulns:
                            component_vulns[component_name] = {}
                        if vuln_key not in component_vulns[component_name]:
                            component_vulns[component_name][vuln_key] = full_vuln
                        
                        # 记录漏洞来源
                        if vuln_key not in vuln_sources:
                            vuln_sources[vuln_key] = []
                        if tool_name and tool_name not in vuln_sources[vuln_key]:
                            vuln_sources[vuln_key].append(tool_name)
        except Exception as e:
            print(f"处理报告 {report_path} 时出错: {str(e)}")
    
    # 处理所有报告，为mobsf报告赋予1.5倍权重
    process_report(jeb_report, 1.0, "JEB")
    process_report(jadx_report, 1.0, "JADX")
    process_report(apktool_report, 1.0, "APKTOOL")
    process_report(flowdroid_report, 1.0, "FLOWDROID")
    process_report(mobsf_report, 1.5, "MOBSF")  # MobSF报告的权重为1.5
    
    # 如果没有找到任何漏洞，返回错误信息
    if not all_vulnerabilities:
        return "未在提供的报告中找到有效的漏洞信息"
    
    # 统计每个组件出现的权重总和
    component_weights = {}
    for comp, _, weight, _ in all_vulnerabilities:
        if comp not in component_weights:
            component_weights[comp] = 0
        component_weights[comp] += weight
    
    # 按组件权重总和降序排序
    sorted_components = sorted(component_weights.keys(), 
                              key=lambda x: component_weights[x], 
                              reverse=True)
    
    # 按组件分组生成报告内容
    sorted_report_content = []
    for component in sorted_components:
        # 添加组件标识行
        # sorted_report_content.append(f"+*/{component}/*+")
        # 添加该组件的所有漏洞
        for vuln_key, vuln_text in component_vulns[component].items():
            # 添加漏洞来源信息
            sources = "/".join(vuln_sources.get(vuln_key, ["未知"]))
            # 在漏洞文本开头添加来源信息
            source_info = f"--**--{vuln_key}_来源({sources})--/**--"
            sorted_report_content.append(source_info)
            sorted_report_content.append(vuln_text)
    
    # 生成报告文件
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.dirname(jeb_report) if jeb_report else os.path.dirname(jadx_report) if jadx_report else os.path.dirname(apktool_report) if apktool_report else os.path.dirname(flowdroid_report) if flowdroid_report else os.path.dirname(mobsf_report) if mobsf_report else os.path.join(os.path.expanduser("~"), "Desktop")
    combined_output_dir = os.path.join(output_dir, "combined_reports")
    os.makedirs(combined_output_dir, exist_ok=True)
    
    output_file = os.path.join(combined_output_dir, f"combined_vulnerability_report_{timestamp}.txt")
    
    # 写入排序后的漏洞内容
    with open(output_file, 'w', encoding='utf-8') as f:
        # 添加报告头信息
        f.write(f"# 综合漏洞分析报告\n\n")
        f.write(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # 添加组件统计信息
        f.write("## 漏洞组件统计\n\n")
        for component in sorted_components:
            f.write(f"- {component}: 权重 {component_weights[component]:.1f}\n")
        
        f.write("\n## 详细漏洞信息\n\n")
        
        # 写入排序后的漏洞内容，以组件为单位进行分组
        f.write("\n".join(sorted_report_content))
    
    prompt=f"""
我现在有一个综合的APK静态分析报告，包含多个工具（JEB、JADX、APKTool、FlowDroid、Mobsf）的分析结果。下是综合报告内容：
{output_file}
报告中的漏洞已经按照组件名称的权重进行排列。请注意，有些组件相同但名称不同的漏洞本质上是相同的漏洞。请你通过阅读报告，分析所有漏洞信息，将相同的漏洞完善合并成一份漏洞描述，不同的漏洞进行保留，形成一份新的报告。
注意将相同的漏洞进行合并的过程中，需要把漏洞的权重进行累加！整合后的漏洞按照如下格式进行保存：
--**--漏洞名称_漏洞的所有来源（eg.mobsf/JEB/...  如果存在多个来源都要记录）--/**--
随后是漏洞的具体信息，每个漏洞块仍旧以--*--开始，以--/*--结束。
注意，请通过大模型本身通过阅读报告对漏洞进行内容的具体分析，而不是撰写脚本来处理报告内容，只有对漏洞信息进行阅读分析才能判断其本质上是否为相同的漏洞。
请将生成的综合报告保存到相同路径下，并确保文件名包含时间戳。

    """
    return prompt

@mcp.tool()
def split_vulnerabilities_by_priority(integrated_report_path: str) -> str:
    """
    将整合后的漏洞报告按权重分类保存到三个不同文件中
    
    Args:
        integrated_report_path: 整合后报告的绝对路径
        
    Returns:
        包含三个文件路径的字符串，分别是高优先级漏洞、低优先级且无MobSF来源的漏洞、低优先级且有MobSF来源的漏洞
    """
    if not os.path.exists(integrated_report_path):
        return f"错误：整合报告文件不存在: {integrated_report_path}"
    
    try:
        # 读取报告内容
        with open(integrated_report_path, 'r', encoding='utf-8') as file:
            report_content = file.read()
        
        # 解析漏洞统计信息和漏洞详情
        vuln_stats = {}
        vuln_sources = {}
        vuln_details = {}
        
        # 提取漏洞来源和详情
        source_pattern = re.compile(r'--\*\*--(.+?)_来源\((.+?)\)--/\*\*--\s+(--\*--.+?--/\*--)', re.DOTALL)
        matches = source_pattern.findall(report_content)
        
        for vuln_name, sources, details in matches:
            vuln_sources[vuln_name] = sources.split('/')
            vuln_details[vuln_name] = f"--**--{vuln_name}_来源({sources})--/**--\n{details}"
        
        # 如果报告中包含权重信息，尝试提取
        weight_pattern = re.compile(r'- (.+?): 权重 (\d+\.\d+)')
        weight_matches = weight_pattern.findall(report_content)
        
        for component, weight in weight_matches:
            vuln_stats[component] = float(weight)
        
        # 如果没有找到权重信息，则假设每个漏洞的权重相等
        if not vuln_stats and vuln_sources:
            for vuln_name in vuln_sources:
                # 根据来源数量估算权重 - 每个来源权重为1，MobSF为1.5
                weight = 0
                for source in vuln_sources[vuln_name]:
                    weight += 1.5 if source.strip().upper() == "MOBSF" else 1.0
                vuln_stats[vuln_name] = weight
        
        # 按权重降序排序
        sorted_vulns = sorted(vuln_stats.items(), key=lambda x: x[1], reverse=True)
        total_vulns = len(sorted_vulns)
        
        # 确定权重阈值（60%分界点）
        split_index = int(total_vulns * 0.6)
        
        # 分离不同类别的漏洞
        high_priority_vulns = []
        low_priority_no_mobsf_vulns = []
        low_priority_with_mobsf_vulns = []
        
        for i, (vuln_name, _) in enumerate(sorted_vulns):
            if i < split_index:
                # 前60%为高优先级
                high_priority_vulns.append(vuln_details.get(vuln_name, ""))
            else:
                # 判断后40%中是否包含MobSF来源
                sources = vuln_sources.get(vuln_name, [])
                has_mobsf = any(source.strip().upper() == "MOBSF" for source in sources)
                
                if has_mobsf:
                    low_priority_with_mobsf_vulns.append(vuln_details.get(vuln_name, ""))
                else:
                    low_priority_no_mobsf_vulns.append(vuln_details.get(vuln_name, ""))
        
        # 生成输出文件
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.dirname(integrated_report_path)
        
        high_priority_file = os.path.join(output_dir, f"high_priority_vulns_{timestamp}.txt")
        low_no_mobsf_file = os.path.join(output_dir, f"low_priority_no_mobsf_vulns_{timestamp}.txt")
        low_with_mobsf_file = os.path.join(output_dir, f"low_priority_with_mobsf_vulns_{timestamp}.txt")
        
        # 写入高优先级漏洞
        with open(high_priority_file, 'w', encoding='utf-8') as f:
            f.write(f"# 高优先级漏洞报告 (前60%权重)\n\n")
            f.write(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"漏洞数量: {len(high_priority_vulns)}\n\n")
            f.write("\n\n".join(high_priority_vulns))
        
        # 写入低优先级无MobSF漏洞
        with open(low_no_mobsf_file, 'w', encoding='utf-8') as f:
            f.write(f"# 低优先级漏洞报告 (后40%权重，无MobSF来源)\n\n")
            f.write(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"漏洞数量: {len(low_priority_no_mobsf_vulns)}\n\n")
            f.write("\n\n".join(low_priority_no_mobsf_vulns))
        
        # 写入低优先级有MobSF漏洞
        with open(low_with_mobsf_file, 'w', encoding='utf-8') as f:
            f.write(f"# 低优先级漏洞报告 (后40%权重，有MobSF来源)\n\n")
            f.write(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"漏洞数量: {len(low_priority_with_mobsf_vulns)}\n\n")
            f.write("\n\n".join(low_priority_with_mobsf_vulns))
        
        return f"""已将漏洞按优先级分类保存至以下文件:
1. 高优先级漏洞 (前60%): {high_priority_file}
2. 低优先级无MobSF来源漏洞: {low_no_mobsf_file}
3. 低优先级有MobSF来源漏洞: {low_with_mobsf_file}
"""
    except Exception as e:
        return f"处理报告时出错: {str(e)}"

@mcp.tool()
def assess_vulnerability_risk(vulnerability_report_path: str) -> str:
    """
    评估漏洞的危险系数，并将评分添加到报告中
    
    Args:
        vulnerability_report_path: 漏洞报告的绝对路径
        
    Returns:
        调用大模型的prompt字符串
    """
    if not os.path.exists(vulnerability_report_path):
        return f"错误：漏洞报告文件不存在: {vulnerability_report_path}"
    
    try:
        # 读取报告内容
        with open(vulnerability_report_path, 'r', encoding='utf-8') as file:
            report_content = file.read()
        
        # 定义输出文件路径
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.dirname(vulnerability_report_path)
        risk_assessed_report_file = os.path.join(output_dir, f"risk_assessed_vulns_{timestamp}.txt")
        
        # 构造prompt
        prompt = f"""
我需要你评估一份APK漏洞报告中每个漏洞的危险系数，评分范围为0-10分。

## 漏洞报告文件路径
{vulnerability_report_path}

## 评分标准
请根据以下因素为每个漏洞评分（0-10分，10分表示最危险）：

1. 攻击影响范围：漏洞可能影响的用户范围和系统范围
2. 漏洞利用难度：攻击者利用该漏洞的技术门槛
3. 漏洞影响程度：可能造成的最严重后果（如数据泄露、远程代码执行、拒绝服务等）
4. 攻击前置条件：触发漏洞所需的前置条件越少，风险越高
5. 权限要求：不需要特殊权限即可触发的漏洞风险更高

评分参考：
- 9-10分：极高风险（如远程代码执行、无需用户交互的权限提升等）
- 7-8分：高风险（敏感信息泄露、需少量用户交互的严重漏洞等）
- 5-6分：中高风险（需要一定前置条件的严重漏洞）
- 3-4分：中等风险（需要多个前置条件或特定场景才能触发的漏洞）
- 1-2分：低风险（利用难度高、影响有限的漏洞）
- 0分：无风险（误报或几乎不可利用的漏洞）

## 任务要求
1. 仔细阅读每个漏洞的详细信息
2. 根据上述评分标准，为每个漏洞分配一个0-10的整数评分
3. 在给每个漏洞评分时，简要说明评分理由（不超过50字）
4. 评分结果应添加在每个漏洞块开始之前，格式为：--评分：X/10 评分理由-/-

## 输出要求
请将评估后的报告保存到以下文件：{risk_assessed_report_file}

报告格式示例：
```
-*-评分：8/10 可导致敏感信息泄露且无需用户交互-/*-
--**--漏洞名称_来源(MOBSF/JEB)--/**--
--*--
漏洞详细信息...
--/*--

-*-评分：3/10 需要多个前置条件且影响有限-/*-
--**--另一个漏洞_来源(JADX)--/**--
--*--
漏洞详细信息...
--/*--
```

请确保评估每一个漏洞，并保持原始报告的其他格式和内容不变。同时，在报告开头添加一个总体风险评估摘要，包含各风险等级的漏洞数量统计。
"""
        
        return prompt
    except Exception as e:
        return f"处理报告时出错: {str(e)}"

@mcp.tool()
def integrate_priority_reports(high_priority_path: str, low_priority_no_mobsf_path: str, risk_assessed_mobsf_path: str) -> str:
    """
    整合不同优先级的漏洞报告
    
    Args:
        high_priority_path: 高优先级漏洞报告的绝对路径（前60%）
        low_priority_no_mobsf_path: 低优先级且无MobSF来源漏洞报告的绝对路径
        risk_assessed_mobsf_path: 经过风险评估的低优先级且有MobSF来源漏洞报告的绝对路径
        
    Returns:
        整合后报告的绝对路径
    """
    # 检查文件是否存在
    for path in [high_priority_path, low_priority_no_mobsf_path, risk_assessed_mobsf_path]:
        if not os.path.exists(path):
            return f"错误：报告文件不存在: {path}"
    
    try:
        # 读取三个报告的内容
        with open(high_priority_path, 'r', encoding='utf-8') as f:
            high_priority_content = f.read()
        
        with open(low_priority_no_mobsf_path, 'r', encoding='utf-8') as f:
            low_no_mobsf_content = f.read()
        
        with open(risk_assessed_mobsf_path, 'r', encoding='utf-8') as f:
            risk_assessed_content = f.read()
        
        # 解析高优先级漏洞
        high_pattern = re.compile(r'(--\*\*--.*?--/\*--)', re.DOTALL)
        high_vulns = high_pattern.findall(high_priority_content)
        
        # 解析低优先级无MobSF漏洞
        low_no_mobsf_vulns = high_pattern.findall(low_no_mobsf_content)
        
        # 解析带评分的MobSF漏洞（格式不同）
        # 这些漏洞的格式是: -*-评分：X/10 评分理由-/*- 后面跟着漏洞详情
        risk_assessed_pattern = re.compile(r'(-\*-评分：.*?--/\*--)', re.DOTALL)
        risk_assessed_vulns = risk_assessed_pattern.findall(risk_assessed_content)
        
        # 获取高优先级漏洞数量
        high_count = len(high_vulns)
        
        # 获取低优先级无MobSF漏洞数量
        low_no_mobsf_count = len(low_no_mobsf_vulns)
        
        # 获取低优先级有MobSF漏洞数量
        risk_assessed_count = len(risk_assessed_vulns)
        
        # 总漏洞数量
        total_vulns = high_count + low_no_mobsf_count + risk_assessed_count
        
        # 生成输出文件
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.dirname(high_priority_path)
        final_report_file = os.path.join(output_dir, f"final_integrated_report_{timestamp}.txt")
        
        # 写入整合报告
        with open(final_report_file, 'w', encoding='utf-8') as f:
            # 写入报告头部信息
            f.write(f"# APK漏洞综合分析报告\n\n")
            f.write(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # 写入漏洞统计信息
            f.write("## 漏洞统计信息\n\n")
            f.write(f"- 高优先级漏洞（前60%）: {high_count} 个\n")
            f.write(f"- 低优先级无MobSF来源漏洞: {low_no_mobsf_count} 个\n")
            f.write(f"- 低优先级有MobSF来源漏洞（已评分）: {risk_assessed_count} 个\n")
            f.write(f"- 总计: {total_vulns} 个漏洞\n\n")
            
            # 第一部分：高优先级漏洞
            f.write("## 第一部分：高优先级漏洞（前60%）\n\n")
            if high_vulns:
                f.write("\n\n".join(high_vulns))
            else:
                f.write("未发现高优先级漏洞。\n")
            
            # 第二部分：低优先级无MobSF来源漏洞
            f.write("\n\n## 第二部分：低优先级无MobSF来源漏洞\n\n")
            if low_no_mobsf_vulns:
                f.write("\n\n".join(low_no_mobsf_vulns))
            else:
                f.write("未发现低优先级无MobSF来源漏洞。\n")
            
            # 第三部分：低优先级有MobSF来源漏洞（带评分）
            f.write("\n\n## 第三部分：低优先级有MobSF来源漏洞（带风险评分）\n\n")
            if risk_assessed_vulns:
                f.write("\n\n".join(risk_assessed_vulns))
            else:
                f.write("未发现低优先级有MobSF来源漏洞。\n")
        
        # 分析风险评分（如果有评分漏洞）
        if risk_assessed_vulns:
            score_pattern = re.compile(r'-\*-评分：(\d+)/10')
            scores = [int(score_pattern.search(vuln).group(1)) for vuln in risk_assessed_vulns if score_pattern.search(vuln)]
            
            if scores:
                avg_score = sum(scores) / len(scores)
                max_score = max(scores)
                high_risk_count = sum(1 for score in scores if score >= 7)
                
                # 将风险分析添加到报告末尾
                with open(final_report_file, 'a', encoding='utf-8') as f:
                    f.write("\n\n## 风险评估摘要\n\n")
                    f.write(f"- 评分漏洞平均风险分: {avg_score:.1f}/10\n")
                    f.write(f"- 最高风险分: {max_score}/10\n")
                    f.write(f"- 高风险漏洞数量（评分≥7）: {high_risk_count} 个\n")
        
        return f"已成功整合三份漏洞报告并保存至: {final_report_file}"
    
    except Exception as e:
        return f"整合报告时出错: {str(e)}"

def main():
    mcp.run("stdio")  # 或使用 "sse" 模式

if __name__ == "__main__":
    main()