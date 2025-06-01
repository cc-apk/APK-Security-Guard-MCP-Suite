# -*- coding: utf-8 -*-
import sys

from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.units import INativeCodeUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.util import DecompilerHelper

from com.pnfsoftware.jeb.client.api import IScript, IconType, ButtonGroupType
from com.pnfsoftware.jeb.core import JebCoreService, ICoreContext, Artifact, RuntimeProjectUtil

from com.pnfsoftware.jeb.core.input import FileInput
from com.pnfsoftware.jeb.core.units import INativeCodeUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.units.code import ICodeUnit
from com.pnfsoftware.jeb.core.output.text import ITextDocument
from com.pnfsoftware.jeb.core.util import DecompilerHelper
from com.pnfsoftware.jeb.core.units.code.android import IApkUnit
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.core.units.code.asm.decompiler import INativeSourceUnit
from java.io import File

import json
import struct
import threading
import traceback
import os
# Python 2.7 changes - use urlparse from urlparse module instead of urllib.parse
from urlparse import urlparse
# Python 2.7 doesn't have typing, so we'll define our own minimal substitutes
# and ignore most type annotations

# Mock typing classes/functions for type annotation compatibility
class Any(object): pass
class Callable(object): pass
def get_type_hints(func):
    """Mock for get_type_hints that works with Python 2.7 functions"""
    hints = {}
    
    # Try to get annotations (modern Python way)
    if hasattr(func, '__annotations__'):
        hints.update(getattr(func, '__annotations__', {}))
    
    # For Python 2.7, inspect the function signature
    import inspect
    args, varargs, keywords, defaults = inspect.getargspec(func)
    
    # Add all positional parameters with Any type
    for arg in args:
        if arg not in hints:
            hints[arg] = Any
            
    return hints
class TypedDict(dict): pass
class Optional(object): pass
class Annotated(object): pass
class TypeVar(object): pass
class Generic(object): pass

# Use BaseHTTPServer instead of http.server
import BaseHTTPServer

class JSONRPCError(Exception):
    def __init__(self, code, message, data=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.data = data

class RPCRegistry(object):
    def __init__(self):
        self.methods = {}

    def register(self, func):
        self.methods[func.__name__] = func
        return func

    def dispatch(self, method, params):
        if method not in self.methods:
            raise JSONRPCError(-32601, "Method '{0}' not found".format(method))

        func = self.methods[method]
        hints = get_type_hints(func)

        # Remove return annotation if present
        if 'return' in hints:
            hints.pop("return", None)

        if isinstance(params, list):
            if len(params) != len(hints):
                raise JSONRPCError(-32602, "Invalid params: expected {0} arguments, got {1}".format(len(hints), len(params)))

            # Python 2.7 doesn't support zip with items() directly
            # Convert to simpler validation approach
            converted_params = []
            param_items = hints.items()
            for i, value in enumerate(params):
                if i < len(param_items):
                    param_name, expected_type = param_items[i]
                    # In Python 2.7, we'll do minimal type checking
                    converted_params.append(value)
                else:
                    converted_params.append(value)

            return func(*converted_params)
        elif isinstance(params, dict):
            # Simplify type validation for Python 2.7
            if set(params.keys()) != set(hints.keys()):
                raise JSONRPCError(-32602, "Invalid params: expected {0}".format(list(hints.keys())))

            # Validate and convert parameters
            converted_params = {}
            for param_name, expected_type in hints.items():
                value = params.get(param_name)
                # Skip detailed type validation in Python 2.7 version
                converted_params[param_name] = value

            return func(**converted_params)
        else:
            raise JSONRPCError(-32600, "Invalid Request: params must be array or object")

rpc_registry = RPCRegistry()

def jsonrpc(func):
    """Decorator to register a function as a JSON-RPC method"""
    global rpc_registry
    return rpc_registry.register(func)

class JSONRPCRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def send_jsonrpc_error(self, code, message, id=None):
        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            }
        }
        if id is not None:
            response["id"] = id
        response_body = json.dumps(response)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self):
        global rpc_registry

        parsed_path = urlparse(self.path)
        if parsed_path.path != "/mcp":
            self.send_jsonrpc_error(-32098, "Invalid endpoint", None)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_jsonrpc_error(-32700, "Parse error: missing request body", None)
            return

        request_body = self.rfile.read(content_length)
        try:
            request = json.loads(request_body)
        except ValueError:  # Python 2.7 uses ValueError instead of JSONDecodeError
            self.send_jsonrpc_error(-32700, "Parse error: invalid JSON", None)
            return

        # Prepare the response
        response = {
            "jsonrpc": "2.0"
        }
        if request.get("id") is not None:
            response["id"] = request.get("id")

        try:
            # Basic JSON-RPC validation
            if not isinstance(request, dict):
                raise JSONRPCError(-32600, "Invalid Request")
            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")
            if "method" not in request:
                raise JSONRPCError(-32600, "Method not specified")

            # Dispatch the method
            result = rpc_registry.dispatch(request["method"], request.get("params", []))
            response["result"] = result

        except JSONRPCError as e:
            response["error"] = {
                "code": e.code,
                "message": e.message
            }
            if e.data is not None:
                response["error"]["data"] = e.data
        except Exception as e:
            traceback.print_exc()
            response["error"] = {
                "code": -32603,
                "message": "Internal error (please report a bug)",
                "data": traceback.format_exc(),
            }

        try:
            response_body = json.dumps(response)
        except Exception as e:
            traceback.print_exc()
            response_body = json.dumps({
                "error": {
                    "code": -32603,
                    "message": "Internal error (please report a bug)",
                    "data": traceback.format_exc(),
                }
            })

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        # Suppress logging
        pass

class MCPHTTPServer(BaseHTTPServer.HTTPServer):
    allow_reuse_address = False

class Server(object):  # Use explicit inheritance from object for py2
    HOST = "localhost"
    PORT = 16161

    def __init__(self):
        self.server = None
        self.server_thread = None
        self.running = False

    def start(self):
        if self.running:
            print("[MCP] Server is already running")
            return

        # Python 2.7 doesn't support daemon parameter in Thread constructor
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True  # Set daemon attribute after creation
        self.running = True
        self.server_thread.start()

    def stop(self):
        if not self.running:
            return

        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread:
            self.server_thread.join()
            self.server = None
        print("[MCP] Server stopped")

    def _run_server(self):
        try:
            # Create server in the thread to handle binding
            self.server = MCPHTTPServer((Server.HOST, Server.PORT), JSONRPCRequestHandler)
            print("[MCP] Server started at http://{0}:{1}".format(Server.HOST, Server.PORT))
            self.server.serve_forever()
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Port already in use (Linux/Windows)
                print("[MCP] Error: Port 13337 is already in use")
            else:
                print("[MCP] Server error: {0}".format(e))
            self.running = False
        except Exception as e:
            print("[MCP] Server error: {0}".format(e))
        finally:
            self.running = False

# A module that helps with writing thread safe ida code.
# Based on:
# https://web.archive.org/web/20160305190440/http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/
import logging
import Queue as queue  # Python 2.7 uses Queue instead of queue
import traceback
import functools

@jsonrpc
def ping():
    """Do a simple ping to check server is alive and running"""
    return "pong"

# implement a FIFO queue to store the artifacts
artifactQueue = list()

def addArtifactToQueue(artifact):
    """Add an artifact to the queue"""
    artifactQueue.append(artifact)

def getArtifactFromQueue():
    """Get an artifact from the queue"""
    if len(artifactQueue) > 0:
        return artifactQueue.pop(0)
    return None

def clearArtifactQueue():
    """Clear the artifact queue"""
    global artifactQueue
    artifactQueue = list()

MAX_OPENED_ARTIFACTS = 10

def getOrLoadApk(filepath):
    engctx = CTX.getEnginesContext()

    if not engctx:
        print('Back-end engines not initialized')
        return

    if not os.path.exists(filepath):
        raise Exception("File not found: %s" % filepath)
    # Create a project
    project = engctx.loadProject('MCPPluginProject')
    base_name = os.path.basename(filepath)
    correspondingArtifact = None
    for artifact in project.getLiveArtifacts():
        if artifact.getArtifact().getName() == base_name:
            # If the artifact is already loaded, return it
            correspondingArtifact = artifact
            break
    if not correspondingArtifact:
        # try to load the artifact, but first check if the queue size has been exceeded
        if len(artifactQueue) >= MAX_OPENED_ARTIFACTS:
            # unload the oldest artifact
            oldestArtifact = getArtifactFromQueue()
            if oldestArtifact:
                # unload the artifact
                print('Unloading artifact: %s because queue size limit exeeded' % oldestArtifact.getArtifact().getName())
                RuntimeProjectUtil.destroyLiveArtifact(oldestArtifact)

        correspondingArtifact = project.processArtifact(Artifact(base_name, FileInput(File(filepath))))
        addArtifactToQueue(correspondingArtifact)
    
    unit = correspondingArtifact.getMainUnit()
    if isinstance(unit, IApkUnit):
            # If the unit is already loaded, return it
            return unit    
    return None

@jsonrpc
def get_manifest(filepath):
    """Get the manifest of the given APK file in path, note filepath needs to be an absolute path"""
    if not filepath:
        return None

    apk = getOrLoadApk(filepath)  # Fixed: use getOrLoadApk function to load the APK
    #get base name
    
    if apk is None:
        # if the input is not apk (e.g. a jar or single dex, )
        # assume it runs in system context
        return None
    
    man = apk.getManifest()
    if man is None:
        return None
    doc = man.getFormatter().getPresentation(0).getDocument()
    text = TextDocumentUtil.getText(doc)
    #engctx.unloadProjects(True)
    return text

@jsonrpc
def get_apk_permissions(filepath):
    """获取指定APK文件AndroidManifest.xml中声明的所有权限，返回权限字符串列表。"""
    print('[MCP][get_apk_permissions] called with filepath:', filepath)
    if not filepath:
        print('[MCP][get_apk_permissions] filepath is empty')
        return None
    apk = getOrLoadApk(filepath)
    if apk is None:
        print('[MCP][get_apk_permissions] getOrLoadApk failed')
        return None
    man = apk.getManifest()
    if man is None:
        print('[MCP][get_apk_permissions] getManifest failed')
        return None
    try:
        doc = man.getFormatter().getPresentation(0).getDocument()
        text = TextDocumentUtil.getText(doc)
        import re
        permissions = re.findall(r'<uses-permission[^>]*android:name\\s*=\\s*\"([^\"]+)\"', text)
        print('[MCP][get_apk_permissions] permissions:', permissions)
        return permissions
    except Exception as e:
        import traceback
        print('[MCP][get_apk_permissions] Exception:', e)
        traceback.print_exc()
        return None

@jsonrpc
def get_apk_components(filepath):
    """获取指定APK文件AndroidManifest.xml中声明的所有四大组件及其属性，返回结构化列表。"""
    print('[MCP][get_apk_components] called with filepath:', filepath)
    if not filepath:
        print('[MCP][get_apk_components] filepath is empty')
        return None
    apk = getOrLoadApk(filepath)
    if apk is None:
        print('[MCP][get_apk_components] getOrLoadApk failed')
        return None
    man = apk.getManifest()
    if man is None:
        print('[MCP][get_apk_components] getManifest failed')
        return None
    try:
        doc = man.getFormatter().getPresentation(0).getDocument()
        text = TextDocumentUtil.getText(doc)
        import re
        components = []
        # 匹配四大组件标签
        for tag in ['activity', 'service', 'receiver', 'provider']:
            pattern = r'<%s([^>]*)>' % tag
            for match in re.finditer(pattern, text):
                attrs = match.group(1)
                # 提取所有属性
                attr_dict = {}
                for attr_match in re.finditer(r'(\w+:\w+)\s*=\s*(["\"][^"\"]*["\"])', attrs):
                    k, v = attr_match.group(1), attr_match.group(2)
                    attr_dict[k] = v.strip('"')
                components.append({'type': tag, 'attributes': attr_dict})
        print('[MCP][get_apk_components] components:', components)
        return components
    except Exception as e:
        import traceback
        print('[MCP][get_apk_components] Exception:', e)
        traceback.print_exc()
        return None

@jsonrpc
def get_method_decompiled_code(filepath, method_signature):
    """Get the decompiled code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
        print('Cannot acquire decompiler for unit: %s' % decomp)
        return

    if not decomp.decompileMethod(method.getSignature()):
        print('Failed decompiling method')
        return

    text = decomp.getDecompiledMethodText(method.getSignature())
    return text


@jsonrpc
def get_class_decompiled_code(filepath, class_signature):
    """Get the decompiled code of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not class_signature:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
        print('Cannot acquire decompiler for unit: %s' % decomp)
        return

    if not decomp.decompileClass(clazz.getSignature()):
        print('Failed decompiling method')
        return

    text = decomp.getDecompiledClassText(clazz.getSignature())
    return text

from com.pnfsoftware.jeb.core.actions import ActionXrefsData, Actions, ActionContext

@jsonrpc
def get_method_callers(filepath, method_signature):
    """
    Get the callers of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    if method is None:
        raise Exception("Method not found: %s" % method_signature)
    actionXrefsData = ActionXrefsData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_XREFS, method.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,actionXrefsData):
        for i in range(actionXrefsData.getAddresses().size()):
            ret.append((actionXrefsData.getAddresses()[i], actionXrefsData.getDetails()[i]))
    return ret

from com.pnfsoftware.jeb.core.actions import Actions, ActionContext, ActionOverridesData
@jsonrpc
def get_method_overrides(filepath, method_signature):
    """
    Get the overrides of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    if method is None:
        raise Exception("Method not found: %s" % method_signature)
    data = ActionOverridesData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_OVERRIDES, method.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,data):
        for i in range(data.getAddresses().size()):
            ret.append((data.getAddresses()[i], data.getDetails()[i]))
    return ret

CTX = None
class MCP(IScript):

    def __init__(self):
        self.server = Server()
        print("[MCP] Plugin loaded")

    def run(self, ctx):
        global CTX  # Fixed: use global keyword to modify global variable
        CTX = ctx
        self.server.start()
        print("[MCP] Plugin running")

    def term(self):
        self.server.stop()

@jsonrpc
def get_apk_info(filepath):
    """获取指定APK文件的基本信息，包括包名、版本号、主Activity等。"""
    print('[MCP][get_apk_info] called with filepath:', filepath)
    if not filepath:
        print('[MCP][get_apk_info] filepath is empty')
        return None
    apk = getOrLoadApk(filepath)
    if apk is None:
        print('[MCP][get_apk_info] getOrLoadApk failed')
        return None
    man = apk.getManifest()
    if man is None:
        print('[MCP][get_apk_info] getManifest failed')
        return None
    try:
        doc = man.getFormatter().getPresentation(0).getDocument()
        text = TextDocumentUtil.getText(doc)
        import re
        info = {}
        # 包名
        m = re.search(r'<manifest[^>]*package\s*=\s*"([^"]+)"', text)
        if m:
            info['package'] = m.group(1)
        # 版本号
        m = re.search(r'android:versionName\s*=\s*"([^"]+)"', text)
        if m:
            info['versionName'] = m.group(1)
        m = re.search(r'android:versionCode\s*=\s*"([^"]+)"', text)
        if m:
            info['versionCode'] = m.group(1)
        # 主Activity
        main_activity = None
        activity_pattern = r'<activity([^>]*)>'
        for match in re.finditer(activity_pattern, text):
            attrs = match.group(1)
            name_match = re.search(r'android:name\s*=\s*"([^"]+)"', attrs)
            if not name_match:
                continue
            activity_name = name_match.group(1)
            # 查找该activity下的intent-filter
            # 取activity标签到下一个activity标签之间的内容
            start = match.end()
            next_activity = text.find('<activity', start)
            if next_activity == -1:
                activity_block = text[start:]
            else:
                activity_block = text[start:next_activity]
            if ('android.intent.action.MAIN' in activity_block and
                'android.intent.category.LAUNCHER' in activity_block):
                main_activity = activity_name
                break
        info['mainActivity'] = main_activity
        print('[MCP][get_apk_info] info:', info)
        return info
    except Exception as e:
        import traceback
        print('[MCP][get_apk_info] Exception:', e)
        traceback.print_exc()
        return None

@jsonrpc
def get_intent_filters(filepath):
    """获取指定APK文件所有组件（Activity/Service/Receiver）的intent-filter及其action/category/data等信息，返回结构化列表。"""
    print('[MCP][get_intent_filters] called with filepath:', filepath)
    if not filepath:
        print('[MCP][get_intent_filters] filepath is empty')
        return None
    apk = getOrLoadApk(filepath)
    if apk is None:
        print('[MCP][get_intent_filters] getOrLoadApk failed')
        return None
    man = apk.getManifest()
    if man is None:
        print('[MCP][get_intent_filters] getManifest failed')
        return None
    try:
        doc = man.getFormatter().getPresentation(0).getDocument()
        text = TextDocumentUtil.getText(doc)
        import re
        results = []
        # 只分析activity/service/receiver
        for tag in ['activity', 'service', 'receiver']:
            tag_pattern = r'<%s([^>]*)>' % tag
            for match in re.finditer(tag_pattern, text):
                attrs = match.group(1)
                name_match = re.search(r'android:name\s*=\s*"([^"]+)"', attrs)
                if not name_match:
                    continue
                comp_name = name_match.group(1)
                # 取该组件标签到下一个同类标签之间的内容
                start = match.end()
                next_tag = text.find('<%s' % tag, start)
                if next_tag == -1:
                    comp_block = text[start:]
                else:
                    comp_block = text[start:next_tag]
                # 查找intent-filter块
                for intent_match in re.finditer(r'<intent-filter>([\s\S]*?)</intent-filter>', comp_block):
                    intent_block = intent_match.group(1)
                    actions = re.findall(r'<action[^>]*android:name\s*=\s*"([^"]+)"', intent_block)
                    categories = re.findall(r'<category[^>]*android:name\s*=\s*"([^"]+)"', intent_block)
                    datas = re.findall(r'<data[^>]*android:([\w:]+)\s*=\s*"([^"]+)"', intent_block)
                    data_dict = {}
                    for k, v in datas:
                        data_dict[k] = v
                    results.append({
                        'component_type': tag,
                        'component_name': comp_name,
                        'actions': actions,
                        'categories': categories,
                        'data': data_dict
                    })
        print('[MCP][get_intent_filters] results:', results)
        return results
    except Exception as e:
        import traceback
        print('[MCP][get_intent_filters] Exception:', e)
        traceback.print_exc()
        return None

@jsonrpc
def get_exported_components(filepath):
    """获取所有exported=true或隐式导出的组件及其属性，返回结构化列表。"""
    print('[MCP][get_exported_components] called with filepath:', filepath)
    if not filepath:
        print('[MCP][get_exported_components] filepath is empty')
        return None
    apk = getOrLoadApk(filepath)
    if apk is None:
        print('[MCP][get_exported_components] getOrLoadApk failed')
        return None
    man = apk.getManifest()
    if man is None:
        print('[MCP][get_exported_components] getManifest failed')
        return None
    try:
        doc = man.getFormatter().getPresentation(0).getDocument()
        text = TextDocumentUtil.getText(doc)
        import re
        results = []
        # 四大组件标签
        for tag in ['activity', 'service', 'receiver', 'provider']:
            tag_pattern = r'<%s([^>]*)>' % tag
            for match in re.finditer(tag_pattern, text):
                attrs = match.group(1)
                name_match = re.search(r'android:name\s*=\s*"([^"]+)"', attrs)
                if not name_match:
                    continue
                comp_name = name_match.group(1)
                # 检查exported属性
                exported_match = re.search(r'android:exported\s*=\s*"([^"]+)"', attrs)
                exported = None
                if exported_match:
                    exported = exported_match.group(1)
                # 隐式导出：没有exported属性但有intent-filter
                # 取该组件标签到下一个同类标签之间的内容
                start = match.end()
                next_tag = text.find('<%s' % tag, start)
                if next_tag == -1:
                    comp_block = text[start:]
                else:
                    comp_block = text[start:next_tag]
                has_intent_filter = re.search(r'<intent-filter>', comp_block) is not None
                # 判断是否导出
                is_exported = False
                if exported == 'true':
                    is_exported = True
                elif exported is None and has_intent_filter:
                    is_exported = True
                if is_exported:
                    # 提取所有属性
                    attr_dict = {}
                    for attr_match in re.finditer(r'(\w+:\w+)\s*=\s*(["\"][^"\"]*["\"])', attrs):
                        k, v = attr_match.group(1), attr_match.group(2)
                        attr_dict[k] = v.strip('"')
                    results.append({'type': tag, 'name': comp_name, 'attributes': attr_dict})
        print('[MCP][get_exported_components] results:', results)
        return results
    except Exception as e:
        import traceback
        print('[MCP][get_exported_components] Exception:', e)
        traceback.print_exc()
        return None

@jsonrpc
def list_broadcast_receivers(filepath):
    """获取所有BroadcastReceiver及其intent-filter信息，返回结构化列表。"""
    print('[MCP][list_broadcast_receivers] called with filepath:', filepath)
    if not filepath:
        print('[MCP][list_broadcast_receivers] filepath is empty')
        return None
    apk = getOrLoadApk(filepath)
    if apk is None:
        print('[MCP][list_broadcast_receivers] getOrLoadApk failed')
        return None
    man = apk.getManifest()
    if man is None:
        print('[MCP][list_broadcast_receivers] getManifest failed')
        return None
    try:
        doc = man.getFormatter().getPresentation(0).getDocument()
        text = TextDocumentUtil.getText(doc)
        import re
        results = []
        tag = 'receiver'
        tag_pattern = r'<%s([^>]*)>' % tag
        for match in re.finditer(tag_pattern, text):
            attrs = match.group(1)
            name_match = re.search(r'android:name\s*=\s*"([^"]+)"', attrs)
            if not name_match:
                continue
            comp_name = name_match.group(1)
            # 取该receiver标签到下一个receiver标签之间的内容
            start = match.end()
            next_tag = text.find('<%s' % tag, start)
            if next_tag == -1:
                comp_block = text[start:]
            else:
                comp_block = text[start:next_tag]
            # 查找intent-filter块
            intent_filters = []
            for intent_match in re.finditer(r'<intent-filter>([\s\S]*?)</intent-filter>', comp_block):
                intent_block = intent_match.group(1)
                actions = re.findall(r'<action[^>]*android:name\s*=\s*"([^"]+)"', intent_block)
                categories = re.findall(r'<category[^>]*android:name\s*=\s*"([^"]+)"', intent_block)
                datas = re.findall(r'<data[^>]*android:([\w:]+)\s*=\s*"([^"]+)"', intent_block)
                data_dict = {}
                for k, v in datas:
                    data_dict[k] = v
                intent_filters.append({
                    'actions': actions,
                    'categories': categories,
                    'data': data_dict
                })
            results.append({
                'name': comp_name,
                'intent_filters': intent_filters
            })
        print('[MCP][list_broadcast_receivers] results:', results)
        return results
    except Exception as e:
        import traceback
        print('[MCP][list_broadcast_receivers] Exception:', e)
        traceback.print_exc()
        return None