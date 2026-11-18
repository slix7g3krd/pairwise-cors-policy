# pairwise-cors-policy

前端跨域调用放开后，CORS 配置就开始放大攻击面：`Access-Control-Allow-Origin: *` 和 `Allow-Credentials: true` 同时出现；Origin 原样反射，任何站点都能带 cookie 读响应；`null` Origin 直接放行，沙箱 iframe 和本地文件都能过；子域通配符信任整个父域，被接管的子域也能读；预检缓存时间过长，权限变更后旧策略还生效；允许的方法和头没有白名单，`DELETE` 和自定义头全放开；错误响应也带 CORS 头；Vary 头缺失导致缓存串站；私有网络访问头没有限制。security/cors_policy.py 是核心，tests/test_cors_policy.py 15个红。要修的是：禁止 `*` 加凭证；Origin 精确匹配；拒绝 `null`；子域逐条校验；预检缓存上限；方法与头白名单；错误响应不放开；补 Vary；限制私有网络。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
