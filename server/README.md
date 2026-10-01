# 更新通道选择

更新包继续由 Nginx 静态分发。服务端 `app/channel_router.py` 使用 Python 标准库，监听 `127.0.0.1:18081`，仅处理程序和引擎的 beta 清单请求。

每次请求读取 `runtime/public/{program,rules}/{stable,beta}/manifest.json`，按数字逐段比较版本。beta 低于 stable 时返回 stable 清单中的下载地址、哈希与签名；beta 相等或更高时返回 beta。响应的 `channel` 保持 `beta`，缓存策略为 `no-store`。beta 缺失、不可用或版本格式无效时使用可用的 stable 清单。

发布时分别更新两个通道的包和原始清单，不要把路由响应写回原始清单。包的 Ed25519 签名保持不变，私钥只用于本地发布。

当前主机部署目录为 `/opt/silverfox-rescue`，服务文件为 `silverfox-channel-router.service`。在 HTTPS Nginx server 中增加两个精确路径：

```nginx
location = /public/program/beta/manifest.json {
    proxy_pass http://127.0.0.1:18081;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
}
location = /public/rules/beta/manifest.json {
    proxy_pass http://127.0.0.1:18081;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
}
```

安装服务后执行 `systemctl daemon-reload` 和 `systemctl enable --now silverfox-channel-router`，通过 `nginx -t` 后重载 Nginx。该服务配置用于主机 Nginx 部署。
