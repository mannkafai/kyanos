---
prev:
  text: '5分钟学会使用kyanos'
  link: './how-to'
next:
  text: 'Stat 使用方法'
  link: './stat'
---

# 抓取请求响应和耗时细节

你可以使用 watch 命令收集你感兴趣的请求响应流量，具体来说，你能够通过watch命令：  

- 查看请求响应的具体内容。
- 查看耗时细节：包括请求到达网卡、响应到达网卡、响应到达 Socket 缓冲区、应用进程读取响应这几个重要的时间点。

从一个最简单的例子开始：

```bash
kyanos watch
```
由于没有指定任何过滤条件，因此 kyanos 会尝试采集所有它能够解析的流量，当前 kyanos 支持三种应用层协议的解析：HTTP、Redis 和 MySQL。

当你执行这行命令之后，你会看到一个表格：
![kyanos watch result](/watch-result.jpg)  


> [!TIP]
> watch 默认采集100条请求响应记录，你可以通过`--max-records`选项来指定


每一列的含义如下：
| 列名称            | 含义                                                                        | 示例                                 |
| :------------- | :------------------------------------------------------------------------ | :--------------------------------- |
| id             | 表示序号                                                                      |                                    |
| Connection     | 表示这次请求响应的连接                                                               | "10.0.4.9:44526 => 169.254.0.4:80" |
| Proto          | 请求响应的协议                                                                   | "HTTP"                             |
| TotalTime      | 这次请求响应的总耗时，单位毫秒                                                           |                                    |
| ReqSize        | 请求大小，单位bytes                                                              |                                    |
| RespSize       | 响应大小，单位bytes                                                              |                                    |
| Net/Internal   | 如果这是本地发起的请求，含义为网络耗时; 如果是作为服务端接收外部请求，含义为本地进程处理的内部耗时                        |                                    |
| ReadSocketTime | 如果这是本地发起的请求，含义为从内核Socket缓冲区读取响应的耗时; 如果是作为服务端接收外部请求，含义从内核Socket缓冲区读取请求的耗时。 |                                    |


按下数字键可以排序对应的列。按`"↑"` `"↓"` 或者 `"k"` `"j"` 可以上下移动选择表格中的记录。按下enter进入这次请求响应的详细界面：

![kyanos watch result detail](/watch-result-detail.jpg)  

详情界面里第一部分是 **耗时详情**，每一个方块代表数据包经过的节点，比如这里有进程、网卡、Socket缓冲区等。  
每个方块下面有一个耗时，这里的耗时指从上个节点到这个节点经过的时间。
可以清楚的看到请求从进程发送到网卡，响应再从网卡复制到 Socket 缓冲区并且被进程读取的流程和每一个步骤的耗时。

第二部分是 **请求响应的具体内容**，分为 Request 和 Response 两部分，超过 1024 字节会截断展示（通过`--max-print-bytes`选项可以调整这个限制）。

## 如何发现你感兴趣的请求响应 {#how-to-filter}
默认 kyanos 会抓取所有它目前支持协议的请求响应，在很多场景下，我们需要更加精确的过滤，比如想要发送给某个远程端口的请求，抑或是某个进程或者容器的关联的请求，又或者是某个 Redis 命令或者HTTP 路径相关的请求。下面介绍如何使用 kyanos 的各种选项找到我们感兴趣的请求响应。


### 根据IP端口过滤
kyanos 支持根据 IP 端口等三/四层信息过滤，可以指定以下选项：

| 过滤条件    | 命令行flag	       | 示例                                                                    |
| :------ | :------------------- | :-------------------------------------------------------------------- |
| 连接的本地端口 | `local-ports`  | `--local-ports 6379,16379` <br> 只观察本地端口为6379和16379的连接上的请求响应               |
| 连接的远程端口 | `remote-ports` | `--remote-ports 6379,16379` <br> 只观察远程端口为6379和16379的连接上的请求响应              |
| 连接的远程ip | `remote-ips`   | `--remote-ips  10.0.4.5,10.0.4.2` <br> 只观察远程ip为10.0.4.5和10.0.4.2的连接上的请求响应 |
| 客户端/服务端 | `side`   | `--side  client/server` <br> 只观察作为客户端发起连接/作为服务端接收连接时的请求响应 |


### 根据进程/容器过滤 {#filter-by-container}

| 过滤条件    | 命令行flag	       | 示例                                                                    |
| :------ | :------------- | :-------------------------------------------------------------------- |
| 进程pid列表   | `pids`          | `--pids 12345,12346` 多个pid按逗号分隔    |
| 容器id   | `container-id`          | `--container-id xx`   |
| 容器名称   | `container-name`          | `--container-name foobar`      |
| k8s pod名称   | `pod-name`          | `--pod-name nginx-7bds23212-23s1s.default` <br> 格式：  NAME.NAMESPACE  |

值得一提的是，kyanos 也会显示容器网卡和宿主机网卡之间的耗时：
![kyanos time detail](/timedetail.jpg)   

### 根据请求响应的一般信息过滤

| 过滤条件    | 命令行flag	       | 示例                                                                    |
| :------ | :------------- | :-------------------------------------------------------------------- |
| 请求响应耗时  | `latency`      | `--latency 100`  只观察耗时超过100ms的请求响应                                    |
| 请求大小字节数 | `req-size`     | `--req-size 1024`  只观察请求大小超过1024bytes的请求响应                            |
| 响应大小字节数 | `resp-size`    | `--resp-size 1024`  只观察响应大小超过1024bytes的请求响应                           |


### 根据协议特定信息过滤
你可选择只采集某种协议的请求响应，通过在 watch 后面加上具体的协议名称，当前支持：

- `http`
- `redis`
- `mysql`

比如：`kyanos watch http --path /foo/bar`, 下面是每种协议你可以使用的选项。

#### HTTP协议过滤

| 过滤条件   | 命令行flag  | 示例                                               |
| :----- | :------- | :----------------------------------------------- |
| 请求Path | `path`   | `--path /foo/bar ` 只观察请求path为/foo/bar            |
| 请求Host | `host`  | `--host www.baidu.com ` 只观察请求Host为www\.baidu.com |
| 请求方法   | `method` | `--method GET` 只观察请求为GET                         |


#### Redis协议过滤

| 过滤条件    | 命令行flag      | 示例                                        |
| :------ | :----------- | :---------------------------------------- |
| 请求命令    | `command`    | `--command GET,SET `只观察请求命令为GET和SET       |
| 请求Key   | `keys`       | `--keys foo,bar `只观察请求key为foo和bar         |
| 请求key前缀 | `key-prefix` | `--method foo:bar `  只观察请求的key前缀为foo\:bar |

#### MYSQL协议过滤

> 已支持MySQL协议抓取，根据条件过滤仍在实现中...


---

> [!TIP]
> 所有上述选项均可以组合使用，比如：`./kyanos watch redis --keys foo,bar --remote-ports 6379 --pid 12345`