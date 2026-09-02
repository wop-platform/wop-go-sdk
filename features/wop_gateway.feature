# WOP 商户 SDK 验收场景（godog/Gherkin）
# 场景 ↔ spec 功能面（F1-F9）映射见每段标注。
# 纪律：入向场景的"平台响应"由 suite 内独立网关模拟器拼装（D5：不复用
# 商户出向代码镜像构造），密钥取黄金向量 fixture。

Feature: 商户接入 WOP 网关
  商户以 WopClient 完成配置、出向签名/加密、入向校验解密的全流程。
  背景:
    Given 黄金向量 fixture 已加载

  # S1 首次接入配置 —— F1 套件解析、密钥格式校验
  Scenario: 商户以合法 RSA3072 套件完成配置
    Given 商户准备 WOP-RSA3072-SHA256 套件的密钥材料
    When 商户创建 WopClient
    Then 配置成功
    And 套件摘要标签为 sha-256
    And 套件报文算法为 AES-256-GCM

  Scenario: 商户误配跨族套件 WOP-RSA3072-SM3 被拒绝
    Given 商户准备跨族套件标识 WOP-RSA3072-SM3
    When 商户创建 WopClient
    Then 配置失败，错误码为 configuration

  Scenario: 商户误配非法格式套件被拒绝
    Given 商户准备非法格式套件标识 RSA3072-SHA256
    When 商户创建 WopClient
    Then 配置失败，错误码为 configuration

  # S2 出向 L0 —— F2 canonical、F3 签名、F4 digest、F9 防重放要素
  Scenario: 商户构建 L0 明文请求
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    When 商户以固定时间戳与 nonce 构建 L0 POST /gateway/orders 请求，报文为 {"amount":100}
    Then 请求草稿携带头 x-wop-appkey 与 x-wop-timestamp 与 x-wop-nonce
    And x-wop-content-digest 以 "sha-256" 开头且为 64 位小写 hex
    And 平台以商户公钥对 canonicalRequest 验签通过

  Scenario: 商户构建无报文 L0 请求时 digest 缺席
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    When 商户以固定时间戳与 nonce 构建 L0 GET /gateway/status 请求，无报文
    Then 请求草稿不携带 x-wop-content-digest
    And 签名头不含 x-wop-content-digest

  Scenario: 相同输入的请求构建可确定性重放
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    When 商户以固定时间戳、nonce 与随机源两次构建同一 L2 请求
    Then 两次请求草稿的字节输出完全一致

  # S3 出向 L2 —— F5 数字信封
  Scenario: 商户构建 L2 全文加密请求
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    When 商户以固定随机源构建 L2 POST /gateway/transfers 请求，报文为 {"card":"6222..."}
    Then 请求草稿携带 x-wop-encrypt 头，格式为 L2;dek=<base64url>
    And 请求体为 {"encrypted":"<base64url>"} JSON 信封
    And 平台以商户私钥解包 DEK 后可解密还原明文

  Scenario: 国密商户构建 SM2-SM3 L2 请求
    Given 商户已创建 WOP-SM2-SM3 客户端
    When 商户以固定随机源构建 L2 POST /gateway/sm/request 请求，报文为 {"g":"m"}
    Then 请求草稿携带 x-wop-encrypt 头，格式为 L2;dek=<base64url>
    And 平台解包后 SM4-GCM 明文与原文一致

  # S4/S5 入向校验 —— F6 固定顺序管线
  Scenario: 商户校验平台 L0 响应成功
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 L0 响应，路径 /gateway/orders，明文 {"code":"SUCCESS"}
    When 商户校验响应
    Then 校验通过且明文为 {"code":"SUCCESS"}

  Scenario: 商户校验平台 L2 响应并解密
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 L2 响应，路径 /gateway/orders，明文 {"secret":true}
    When 商户校验响应
    Then 校验通过且明文为 {"secret":true}

  Scenario: 商户校验平台回调（URI 取回调 path，方法恒 POST）
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 L0 回调，回调地址 https://merchant.example/wop/callback?chan=pay，明文 {"event":"PAID"}
    When 商户校验回调
    Then 校验通过且明文为 {"event":"PAID"}

  # S4 负向 —— I2 先验签、I7 模糊、D2 摘要复核、F7 编码、I3/D8 一致性
  Scenario: 平台响应体被篡改时摘要复核拒绝
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 L0 响应，路径 /gateway/orders，明文 {"code":"SUCCESS"}
    And 中间人篡改响应体一个字节
    When 商户校验响应
    Then 校验失败，错误码为 integrity

  Scenario: 平台签名被替换时验签失败且文案模糊
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 L0 响应，路径 /gateway/orders，明文 {"code":"SUCCESS"}
    And 中间人替换签名为另一条合法签名
    When 商户校验响应
    Then 校验失败，错误码为 signature
    And 错误文案为固定模糊文案 "签名验证失败"

  Scenario: 响应携带带 = 填充的 base64url 签名被拒
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 L0 响应，路径 /gateway/orders，明文 {"code":"SUCCESS"}
    And 中间人在签名末尾追加 =
    When 商户校验响应
    Then 校验失败，错误码为 parse

  Scenario: 响应套件与客户端配置不符被拒
    Given 商户已创建 WOP-RSA4096-SHA256 客户端
    And 平台模拟器以 WOP-RSA3072-SHA256 套件产出 L0 响应，路径 /gateway/orders，明文 {"code":"SUCCESS"}
    When 商户校验响应
    Then 校验失败，错误码为 parse

  Scenario: 平台 DEK 载荷 alg 跨族时一致性拒绝
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 alg 跨族的 L2 响应，路径 /gateway/orders，明文 {"secret":true}
    When 商户校验响应
    Then 校验失败，错误码为 consistency

  Scenario: 平台 DEK 密钥错误时 GCM 解密失败且文案模糊
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 DEK 密钥错误的 L2 响应，路径 /gateway/orders，明文 {"secret":true}
    When 商户校验响应
    Then 校验失败，错误码为 decrypt
    And 错误文案为固定模糊文案 "解密失败"

  # S6 一站式 Do —— 概念 API Do + Transport 可插拔
  Scenario: 商户以注入 Transport 一站式调用并校验 L2 响应
    Given 商户已创建 WOP-RSA3072-SHA256 客户端
    And 平台模拟器产出 L2 响应，路径 /gateway/orders，明文 {"ok":1}
    And 网关 Transport 被注入为模拟网关
    When 商户以固定随机源发起 Do POST /gateway/orders L2 调用
    Then 调用成功且明文为 {"ok":1}
    And 模拟网关收到的请求可被平台侧完整校验
