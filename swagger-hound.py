# -*- coding: utf-8 -*-
# https://github.com/evilc0deooo/SwaggerHound

import json
import sys
import csv
import argparse
import requests
import re
import random
import urllib3
from datetime import datetime
from urllib.parse import urlparse
from loguru import logger

# 禁用安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger.remove()
handler_id = logger.add(sys.stderr, level='DEBUG')  # 设置输出级别

now_time = datetime.now().strftime("%Y%m%d_%H%M%S")

proxies = {
    'https': 'http://127.0.0.1:7890',
    'http': 'http://127.0.0.1:7890'
}

# 开启代理
SET_PROXY = False

header_agents = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.96.2 Chrome/128.0.6613.186 Electron/32.2.6 Safari/537.36'
]


def http_req(url, method='get', **kwargs):
    kwargs.setdefault('verify', False)
    kwargs.setdefault('timeout', (10.1, 30.1))
    kwargs.setdefault('allow_redirects', False)

    headers = kwargs.get('headers', {})
    headers.setdefault('User-Agent', random.choice(header_agents))
    # 不允许缓存，每次请求都获取服务器上最新的资源
    headers.setdefault('Cache-Control', 'max-age=0')
    kwargs['headers'] = headers
    if SET_PROXY:
        kwargs['proxies'] = proxies

    conn = getattr(requests, method)(url, **kwargs)
    return conn


def check_page(url):
    """
    检查当前页面
    """
    res = http_req(url, method='get')
    if '<html' in res.text:
        logger.debug('[+] 输入为 swagger 首页，开始解析 api 文档地址')
        return 3  # swagger-html
    elif '"parameters"' in res.text:
        logger.debug('[+] 输入为 api 文档地址，开始构造请求发包')
        return 2  # api_docs
    elif '"location"' in res.text:
        logger.debug('[+] 输入为 resource 地址，开始解析 api 文档地址')
        return 1  # resource


def fill_parameters(parameters, url):
    """
    填充测试数据并替换 URL 中的占位符
    """
    filled_params = {}
    path_params = {}
    for param in parameters:
        param_name = param['name']
        param_in = param['in']
        param_type = param['type']

        # 根据类型填充默认值
        if param_type == 'string':
            value = 'a'
        elif param_type == 'integer':
            value = 1
        elif param_type == 'boolean':
            value = True
        else:
            value = ''

        if param_in == 'query':
            filled_params[param_name] = value
        elif param_in == 'path':
            path_params[param_name] = value
            filled_params[param_name] = value
        elif param_in == 'body':
            if 'body' not in filled_params:
                filled_params['body'] = {}
            filled_params['body'][param_name] = value

    # 替换 URL 中的占位符
    for key, value in path_params.items():
        url = url.replace(f'{{{key}}}', str(value))

    return filled_params, url


def get_api_docs_path(resource_url):
    """
    输入 resource 解析 api 文档 url
    """
    domain = urlparse(resource_url)
    domain = domain.scheme + '://' + domain.netloc
    try:
        res = http_req(resource_url, method='get')
        resources = json.loads(res.text)
    except Exception as e:
        logger.error(f'[-] {resource_url} error info {e}')
        return []

    paths = []
    if isinstance(resources, tuple):
        if 'apis' in resources.keys():  # 版本不同, 格式不一样
            for api_docs in resources.get('apis', {}):
                paths.append(domain + api_docs['path'])
            return paths
    else:
        for i in resources:
            paths.append(domain + i['location'])
        return paths


def output_to_csv(data):
    _f = open(f'{now_time}.csv', 'a', newline='', encoding='utf-8')  # 使用追加模式
    writer = csv.writer(_f)
    writer.writerow(data)


def go_resources(url):
    """
    解析 swagger-resources 获取 api-docs
    """
    try:
        _domain = urlparse(url)
        domain = _domain.scheme + '://' + _domain.netloc
        domain_path = _domain.path
        stripped_path = domain_path.strip('/')
        res = http_req(url)
        data = json.loads(res.text)
        for _i in data:
            location = _i.get('location')
            # 判断如果不存在路径则直接进行拼接
            target = domain + location
            if len(stripped_path) > 0:
                # 如果存在路径则在原路径上继续拼接
                target = url.rsplit('/', 1)[0] + location
            go_api_docs(target)  # 调用 api_docs 扫描全部接口

    except Exception as e:
        logger.error(f'[-] {url} error info {e}')


def go_swagger_html(url):
    """
    解析 swagger-ui.html 获取 api 接口路径
    """
    response = http_req(url)
    response.raise_for_status()
    html_content = response.text
    # 在 swagger-initializer.js 中获取 swagger.json 接口
    initializer_pattern = r'<script\s+src=["\']([^"\']*swagger-initializer\.js[^"\']*)["\']'
    initializer_match = re.search(initializer_pattern, html_content)
    if initializer_match:
        js_file_path = initializer_match.group(1)
        if js_file_path.startswith('http'):
            js_file_url = js_file_path
        else:
            _domain = urlparse(url)
            domain = _domain.scheme + '://' + _domain.netloc
            domain_path = _domain.path
            stripped_path = domain_path.strip('/')
            if len(stripped_path) > 0:
                base_url = url.rsplit('/', 1)[0]
                js_file_url = f'{base_url}/{js_file_path.lstrip("/")}'
            else:
                js_file_url = f'{domain}/{js_file_path.lstrip("/")}'

        js_response = http_req(js_file_url)
        js_response.raise_for_status()
        js_content = js_response.text

        # 正则获取 defaultDefinitionUrl 的值 swagger.json 接口路径
        js_pattern = r'const\s+defaultDefinitionUrl\s*=\s*["\']([^"\']+)["\'];'
        js_match = re.search(js_pattern, js_content)
        if js_match:
            api_docs_path = js_match.group(1)
            go_api_docs(api_docs_path)
            return

    # 未找到 swagger-initializer.js 文件或 defaultDefinitionUrl 定义, 则尝试查找 springfox.js 文件
    springfox_pattern = r'<script\s+src=["\']([^"\']*springfox\.js[^"\']*)["\']'
    springfox_match = re.search(springfox_pattern, html_content)
    if not springfox_match:
        logger.debug('[-] 未找到 swagger-initializer.js 和 springfox.js 文件路径')
        return

    # 获取 springfox.js 文件的相对或绝对路径
    springfox_file_path = springfox_match.group(1)
    if springfox_file_path.startswith('http'):
        springfox_file_url = springfox_file_path
    else:
        base_url = url.rsplit('/', 1)[0]
        springfox_file_url = f'{base_url}/{springfox_file_path.lstrip("/")}'

    # 发送请求获取 springfox.js 文件内容
    springfox_response = http_req(springfox_file_url)
    springfox_response.raise_for_status()
    springfox_content = springfox_response.text
    if "/swagger-resources" in springfox_content:
        base_url = url.rsplit('/', 1)[0]
        resource_url = f"{base_url}/swagger-resources"
        go_resources(resource_url)
        return


def go_api_docs(url):
    """
    开始 api-docs 解析并扫描
    """
    try:
        domain = urlparse(url)
        domain = domain.scheme + '://' + domain.netloc

        res = http_req(url)
        if res.status_code != 200:
            logger.error(f'[-] {url} req status is {res.status_code}')
            return
        try:
            data = json.loads(res.text)
        except json.JSONDecodeError:
            # 遇到 html 标签内存在双引号 json.loads 无法格式化, 需要特殊处理
            data = res.text.replace("'", '"')
            result = re.sub(r'<[^>]*>', lambda match: match.group(0).replace('"', "'"), data)
            data = json.loads(result, strict=False)

        if 'basePath' in data.keys():
            base_path = data['basePath']
        elif 'servers' in data.keys():
            base_path = data['servers']['url']
        else:
            base_path = ''

        paths = data.get('paths', {})
        definitions = data.get('definitions', {})
        swagger_result = []
        for path, methods in paths.items():
            for method, details in methods.items():  # get / post / put / update / delete / head...
                if method.upper() not in ['GET', 'POST']:  # http 请求方式白名单
                    continue
                req_path = domain + base_path + path
                summary = details.get('summary', path)  # 概要信息
                consumes = details.get('consumes', [])  # 数据请求类型 application/json
                params = details.get('parameters', [])
                logger.debug(f'test on {summary} => {method} => {req_path}')
                param_info = []
                for param in params:
                    param_name = param.get('name')
                    param_in = param.get('in')
                    schema = param.get('schema')
                    # 判断是否存在自定义的模型或对象
                    if schema and '$ref' in schema:
                        ref = schema['$ref'].split('/')[-1]
                        if ref in definitions:  # 如果在 definitions 中声明了参数属性，则去 definitions 定义中获取参数及属性信息
                            # 递归处理定义中的属性
                            for prop_name, prop_details in definitions[ref].get('properties', {}).items():
                                param_info.append({
                                    'name': prop_name,
                                    'in': param_in,
                                    'type': prop_details.get('type')
                                })
                    else:
                        param_type = param.get('type')
                        param_info.append({
                            'name': param_name,
                            'in': param_in,
                            'type': param_type
                        })

                # 解析 swagger 获取到所有需要的数据
                swagger_result.append({
                    'summary': summary,
                    'req_path': req_path,
                    'method': method,
                    'consumes': consumes,
                    'parameters': param_info
                })

        black_list_status = [401, 404, 502, 503]  # 状态码黑名单
        for item in swagger_result:
            summary = item['summary']
            req_path = item['req_path']
            method = item['method']
            consumes = item['consumes']
            parameters = item['parameters']
            # 生成发送的 Body 数据
            filled_params, new_url = fill_parameters(parameters, req_path)
            headers = {}

            if 'application/json' in consumes:
                headers = {'Content-Type': 'application/json'}
            if method.lower() == 'get':
                response = http_req(new_url, method='get', params=filled_params)
                if response.status_code in black_list_status:
                    logger.debug(f'[-] {method} {new_url} req status is {response.status_code}')
                    continue
                if response.status_code == 200:
                    logger.debug(f'[+] {method} {new_url} req status is {response.status_code}')
                    write_result = [url, new_url, summary, method, consumes, filled_params, response.status_code, response.text]
                    output_to_csv(write_result)

            elif method.lower() == 'post':
                if 'body' in filled_params:
                    response = http_req(new_url, method='post', json=filled_params['body'], headers=headers)
                    if response.status_code in black_list_status:
                        logger.debug(f'[-] {method} {new_url} req status is {response.status_code}')
                        continue
                    if response.status_code == 200:
                        logger.debug(f'[+] {method} {new_url} req status is {response.status_code}')
                        write_result = [url, new_url, summary, method, consumes, filled_params, response.status_code, response.text]
                        output_to_csv(write_result)

                else:
                    response = http_req(new_url, method='post', params=filled_params, headers=headers)
                    if response.status_code in black_list_status:
                        logger.debug(f'[-] {method} {new_url} req status is {response.status_code}')
                        continue
                    if response.status_code == 200:
                        logger.debug(f'[+] {method} {new_url} req status is {response.status_code}')
                        write_result = [url, new_url, summary, method, consumes, filled_params, response.status_code, response.text]
                        output_to_csv(write_result)


    except Exception as e:
        logger.error(f'[-] {url} error info {e}')


def run(target):
    """
    执行程序
    """
    url_type = check_page(target)
    if url_type == 1:
        logger.success('working on {}'.format(target), 'type: source')
        go_resources(target)
    elif url_type == 2:
        logger.success('working on {}'.format(target), 'type: api-docs')
        go_api_docs(target)
    else:
        logger.success('working on {}'.format(target), 'type: html')
        go_swagger_html(target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', dest='target_url', help='resource 地址 or api 文档地址 or swagger 首页地址')
    parser.add_argument('-f', '--file', dest='url_file', help='批量测试')
    args = parser.parse_args()

    logger.add('debug.log', format='{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}')
    if args.target_url:
        run(args.target_url)
    elif args.url_file:
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f.readlines()]
        for target_url in urls:
            print(target_url)
            run(target_url)
