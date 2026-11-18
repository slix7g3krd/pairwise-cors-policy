"""Hardened CORS policy helpers.

设计原则（对应攻击面收敛清单）：

1. 禁止 ``Access-Control-Allow-Origin: *`` 与 ``Allow-Credentials: true``
   同时出现——凭证响应只允许回显具体的可信 Origin。
2. Origin 精确匹配：只回显白名单中的完整 Origin，不做后缀匹配，
   因此 ``https://sub.app.example`` 不会因为信任 ``https://app.example``
   而被放行（子域必须逐条加入白名单）。
3. 拒绝序列化值为 ``null`` 的 Origin（沙箱 iframe、``file:`` 本地文件、
   重定向跨域等场景都会产生它）。
4. 预检结果缓存设上限，权限收紧后旧策略不会长期残留。
5. 预检方法与请求头走白名单，``DELETE``、自定义头默认全部拒绝；
   私有网络访问（PNA）预检头一律拒绝。
6. 仅当策略判定放行时才输出 CORS 头；拒绝/错误响应不附带任何 CORS 头，
   并通过 ``Vary: Origin`` 防止缓存把一个站点的响应串给另一个站点。

所有函数均为纯函数，不依赖任何第三方库。
"""

# 预检缓存（Access-Control-Max-Age）上限，单位秒。
# 取值区间为 [0, MAX_AGE_LIMIT)；600 秒及以上一律拒绝，避免权限变更后
# 浏览器仍长期持有旧的预检授权。
MAX_AGE_LIMIT = 600

# 私有网络访问（Private Network Access）预检请求头。
# 浏览器在请求内网资源前会带 Access-Control-Request-Private-Network: true，
# 本策略不允许公权页面访问私有网络，出现即拒绝。
PRIVATE_NETWORK_REQUEST_HEADER = 'access-control-request-private-network'


def is_null_origin(origin):
    """判断 Origin 是否为序列化的 ``null``。

    浏览器在沙箱 iframe（``sandbox`` 未授予 allow-same-origin）、
    ``file:``/``data:`` 文档、跨域重定向等场景下会把 Origin 序列化为
    字符串 ``null``，它不代表任何可信来源，必须拒绝。

    >>> is_null_origin('null')
    True
    >>> is_null_origin('https://app.example')
    False
    >>> is_null_origin('')
    False
    """
    return origin == 'null'


def allow_origin(origin, allowed_origins):
    """按精确白名单校验 Origin，返回可回显的 Origin 或 ``None``。

    - 空值、``null``、通配符 ``*`` 一律不放行；
    - 仅当 Origin 与白名单中的某条 **完全相等**（区分大小写、不做后缀
      匹配）时才回显该 Origin，子域需逐条加入白名单；
    - 未放行时返回 ``None``，调用方不得在响应中附带任何 CORS 头，
      错误响应同样保持封闭。

    :param origin: 请求头中的 Origin 值。
    :param allowed_origins: 可信 Origin 的集合（``set[str]``）。
    :return: 校验通过时原样返回 Origin，否则返回 ``None``。
    """
    if not isinstance(origin, str) or not origin:
        return None
    # null Origin 与通配符永不回显。
    if is_null_origin(origin) or origin == '*':
        return None
    if not isinstance(allowed_origins, (set, frozenset, tuple, list)):
        return None
    # 精确匹配：区分大小写、不做任何后缀/子域推导。
    if origin in allowed_origins:
        return origin
    return None


def allow_credentials(origin, credentials):
    """判定是否允许发送凭证（Cookie、TLS 客户端证书等）。

    凭证响应的 ``Access-Control-Allow-Origin`` 必须是具体 Origin，
    禁止与通配符 ``*`` 或 ``null`` 组合：

    >>> allow_credentials('*', True)
    False
    >>> allow_credentials('https://app.example', True)
    True
    >>> allow_credentials('https://app.example', False)
    False
    """
    if not credentials:
        return False
    if not isinstance(origin, str) or not origin:
        return False
    if origin == '*' or is_null_origin(origin):
        return False
    return True


def preflight(method, headers, allowed_methods, allowed_headers):
    """校验 OPTIONS 预检请求是否符合白名单策略。

    通过条件（任一不满足即拒绝，返回 ``False`` 且响应不带任何 CORS 头）：

    1. 请求方法在方法白名单内（精确匹配）；
    2. 每个 ``Access-Control-Request-Headers`` 中的请求头都在请求头
       白名单内——HTTP 头名大小写不敏感，按小写归一后比较；
    3. 不包含私有网络访问预检头
       ``Access-Control-Request-Private-Network``。

    :param method: ``Access-Control-Request-Method`` 的值。
    :param headers: ``Access-Control-Request-Headers`` 解析后的头名列表。
    :param allowed_methods: 允许的 HTTP 方法集合。
    :param allowed_headers: 允许的自定义请求头集合。
    """
    # 方法白名单：精确匹配，DELETE 等未列出的方法默认拒绝。
    if not isinstance(method, str) or method not in allowed_methods:
        return False

    if not isinstance(headers, (list, tuple, set, frozenset)):
        return False

    # 头名大小写不敏感，统一归一为小写后比对。
    normalized_allowed = {h.lower() for h in allowed_headers}
    for header in headers:
        if not isinstance(header, str):
            return False
        normalized = header.strip().lower()
        if not normalized:
            return False
        # 私有网络访问预检头：公网页面不得借此访问内网。
        if normalized == PRIVATE_NETWORK_REQUEST_HEADER:
            return False
        # 请求头白名单：未列出的自定义头默认拒绝。
        if normalized not in normalized_allowed:
            return False
    return True


def max_age_ok(max_age):
    """校验预检缓存时间 ``Access-Control-Max-Age`` 是否在上限内。

    仅接受 [0, ``MAX_AGE_LIMIT``) 区间内的非负整数；过长的缓存会让
    权限收紧后浏览器仍沿用旧授权：

    >>> max_age_ok(600)
    False
    >>> max_age_ok(300)
    True
    """
    if isinstance(max_age, bool) or not isinstance(max_age, int):
        return False
    return 0 <= max_age < MAX_AGE_LIMIT


def vary_header(origin):
    """返回需要写入的 ``Vary`` 头值。

    对具体 Origin 的响应必须带 ``Vary: Origin``，否则共享缓存可能把
    针对一个 Origin 生成的响应（含按 Origin 回显的 CORS 头）发给另一个
    Origin，造成缓存串站。空 Origin 或 ``null`` 不放行，返回 ``None``。
    """
    if not isinstance(origin, str) or not origin:
        return None
    if is_null_origin(origin):
        return None
    return 'Origin'
