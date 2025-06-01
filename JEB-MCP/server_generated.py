# NOTE: This file has been automatically generated, do not modify!
# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
from typing import Annotated, Optional, TypedDict, Generic, TypeVar
from pydantic import Field

T = TypeVar("T")

@mcp.tool()
def ping() -> str:
    """Do a simple ping to check server is alive and running"""
    return make_jsonrpc_request('ping')

@mcp.tool()
def get_manifest(filepath: str) -> str:
    """Get the manifest of the given APK file in path, the passed in filepath needs to be a fully-qualified absolute path"""
    return make_jsonrpc_request('get_manifest', filepath)

@mcp.tool()
def get_apk_permissions(filepath: str) -> list:
    """获取指定APK文件AndroidManifest.xml中声明的所有权限，返回权限字符串列表。"""
    return make_jsonrpc_request('get_apk_permissions', filepath)

@mcp.tool()
def get_method_decompiled_code(filepath: str, method_signature: str) -> str:
    """Get the decompiled code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
        
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z

    @param filepath: the path to the APK file
    @param method_signature: the fully-qualified method signature to decompile, e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request('get_method_decompiled_code', filepath, method_signature)

@mcp.tool()
def get_class_decompiled_code(filepath: str, class_signature: str) -> str:
    """Get the decompiled code of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:

    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z

    @param: filepath: The path to the APK file
    @param: class_signature: The fully-qualified signature of the class to decompile, e.g. Lcom/abc/Foo;
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request('get_class_decompiled_code', filepath, class_signature)

@mcp.tool()
def get_method_callers(filepath: str, method_signature: str) -> list[(str,str)]:
    """
    Get the callers of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request('get_method_callers', filepath, method_signature)

@mcp.tool()
def get_method_overrides(filepath: str, method_signature: str) -> list[(str,str)]:
    """
    Get the overrides of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    return make_jsonrpc_request('get_method_overrides', filepath, method_signature)

@mcp.tool()
def get_apk_components(filepath: str) -> list:
    """获取指定APK文件AndroidManifest.xml中声明的所有四大组件及其属性，返回结构化列表。"""
    return make_jsonrpc_request('get_apk_components', filepath)

@mcp.tool()
def get_apk_info(filepath: str) -> dict:
    """获取指定APK文件的基本信息，包括包名、版本号、主Activity等。"""
    return make_jsonrpc_request('get_apk_info', filepath)

@mcp.tool()
def get_intent_filters(filepath: str) -> list:
    """获取指定APK文件所有组件（Activity/Service/Receiver）的intent-filter及其action/category/data等信息，返回结构化列表。"""
    return make_jsonrpc_request('get_intent_filters', filepath)

@mcp.tool()
def get_exported_components(filepath: str) -> list:
    """获取所有exported=true或隐式导出的组件及其属性，返回结构化列表。"""
    return make_jsonrpc_request('get_exported_components', filepath)

@mcp.tool()
def list_broadcast_receivers(filepath: str) -> list:
    """获取所有BroadcastReceiver及其intent-filter信息，返回结构化列表。"""
    return make_jsonrpc_request('list_broadcast_receivers', filepath)