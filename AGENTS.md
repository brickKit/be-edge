# be-edge

边缘的会话层（线协议 `be-protocol` 第 11 章 P11.1–P11.10）：Traefik 的 Yaegi 插件，核心以后也给别的边缘产品的旁挂外壳用。用法在 `README.md`；为什么这样设计在装配项目 be-assembly-standard 的 A118、A119、协议 20 的登录与会话、底层选择的边缘入口。

## 代码地图

| 文件 | 内容 |
| --- | --- |
| `edge.go` | 配置、`New`（Traefik 每个路由、每次重载都调一次）、处理器：剥掉浏览器的 `Authorization`、注入令牌、`BE-Request`、`TOKEN_STALE` 重放一次、登出、`features` |
| `interceptor.go` | 组件的回答直接写出，只有 401 先扣下，看是不是 `TOKEN_STALE` |
| `sessions.go` | 按会话摘要的令牌缓存（包级变量，重载不丢）、同一会话同时只换取一次、已结束会话的轮询 |
| `identity.go` | 身份成员的客户端：HTTP/2 上手写 gRPC 分帧、静态的 TLS 配置、证书文件变了就换传输 |
| `wire.go` | `be.session.v1` 消息的手写编解码 |
| `.traefik.yml` | Traefik 的插件清单（`basePkg: edge`：导入路径以 `/v3` 结尾） |
| `tests/` | 另一个模块：协议向量、对 grpc-go 的互通、真实 Traefik 容器里的插件 |

## 不能弄坏的

| 不许 | 症状 | 原因 |
| --- | --- | --- |
| 根包导入标准库以外的东西 | Traefik 加载插件失败，全部中间件停用 | Yaegi 只认标准库；protobuf、grpc-go 用了 `unsafe` |
| 让标准库回调解释执行的代码（`tls.Config` 的 `GetClientCertificate`、`VerifyConnection` 之类） | TLS 握手里 panic，整个 Traefik 进程退出 | Yaegi v0.16.1 的反射赋值错误（`reflect.Set: value of type *tls.CertificateRequestInfo is not assignable ...`）；单元测试里看不出来，只有对真实服务器握手时才出 |
| 插件里起的 goroutine 不 `recover` | 一个 panic 带走整个边缘 | Traefik 的恢复中间件只接住处理请求时的 panic |
| 缓存放在中间件实例里 | Docker 每次增减容器（配置重载）都清空缓存，所有会话重新换取 | 重载会再调一次 `New` |
| 用泛型、`for range n`、内建的 `min`/`max` 等较新的写法 | 编译器下通过，Yaegi 下失败 | 解释器跟不上；`yaegi test .` 会发现 |
| 改会话摘要的算法 | 换取全部失败 | 身份成员按 Cookie 值的小写十六进制 SHA-256 存会话（P8.28） |

## 构建与测试

见 `README.md` 的 Tests：改了根包，两种方式（Go 编译器、`yaegi test .`）都要跑；改了与 Traefik 或 TLS 有关的部分，再跑 `tests/` 的 `-tags traefik`。规则写在实现之后、第一次就绿的测试，照装配项目的测试规范做改坏代码的反向检查。

## 版本

`v3.0.0-alpha.N`（装配项目的 A110：全部仓库从 3.0.0 起，开发阶段只升最后一位）；每次改动都升，带注释的标签。
