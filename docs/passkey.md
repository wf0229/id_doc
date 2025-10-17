# 通行密钥

「通行密钥」是存储在你的移动设备上的加密密钥。通过验证你的生物信息（如指纹、面容识别）来验证这个密钥，无需输入复杂的密码，即可快速登录中国科大统一身份认证。
```mermaid
flowchart LR
  %% 样式定义
  classDef person fill:#c5f3e0,stroke:#24927a,stroke-width:1px,rx:8,ry:8;
  classDef device fill:#d9eaf7,stroke:#3a7ca5,stroke-width:1px,rx:8,ry:8;
  classDef box fill:#fdf6e3,stroke:#b58900,stroke-width:1px,rx:8,ry:8;
  classDef note fill:#fff,stroke:#999,stroke-dasharray:3 3,rx:8,ry:8;

  %% 节点定义
  U[🧑用户<br/>USTCer]:::person
  D[🔐设备<br/>钥匙存在设备安全区域]:::device
  S[🌐网站<br/>统一身份认证]:::box

  %% 连线
  U -->|可以解锁设备<br/>从而解锁“钥匙”| D
  D -->|“钥匙认证”不会泄露钥匙| S
```

## 「通行密钥」安全性证明
[N. Binde, C. Cremers and M. Zhao, "FIDO2, CTAP 2.1, and WebAuthn 2: Provable Security and Post-Quantum Instantiation," 2023 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2023, pp. 1471-1490, doi: 10.1109/SP46215.2023.10179454.](https://doi.org/10.1109/SP46215.2023.10179454)

## 通行密钥 注册原理-创建钥匙
```mermaid
sequenceDiagram
    participant U as 🧑 USTCer
    participant D as 🔐 设备
    participant P as 🌐 身份认证系统

    U->>P: 1.我要试试通行密钥
    P-->>D: 2.请帮"你的主人"做一把独一无二的“数字钥匙”
    D->>D: 3.在设备里安全地造一把钥匙<br/>（只留在自己设备上）
    D-->>P: 4.把“钥匙印章”交给网站保存
    P-->>U: 5.注册完成，下次登录用这把钥匙就行啦！
```

## 通行密钥 登录原理-使用钥匙
```mermaid
sequenceDiagram
    participant U as 🧑 USTCer
    participant D as 🔐 设备（手机/电脑）
    participant P as 🌐 身份认证系统

    U->>P: 1.USTCer想用通行密钥登录
    P-->>D: 2.请验证他是否真的是"你的主人"
    D->>U: 3.你能解锁这个设备吗？
    U->>D: 4.解锁成功，确认通过
    D-->>P: 5.验证通过，没问题！
    P-->>U: 6.欢迎回来 👋
```

## 「通行密钥」安全吗？

与传统密码相比，「通行密钥」更加安全，因为：

- **免受密码泄露的风险**  
  传统密码容易被泄露或猜测，尤其是在不同应用程序使用相同密码或弱密码的情况下。而「通行密钥」通过设备的生物识别进行验证，彻底消除了密码被破解、盗取或泄露的风险。

- **防止钓鱼攻击**  
  传统密码容易成为钓鱼攻击的目标，我们可能在不知情的情况下输入密码到伪造的网站。而「通行密钥」基于非对称加密的安全方案，登录过程中不需要输入密码，因此即使遭遇钓鱼攻击，攻击者也无法获取用户的登录信息。

- **基于设备和生物识别**  
  「通行密钥」是与特定设备绑定的，只保留在设备端，也只有通过设备的生物识别（如指纹、面容识别）才能完成登录。这意味着即使攻击者获取了设备，也无法通过自己的生物信息验证、访问账号。

```mermaid
flowchart TB
    %% Passkey 安全原理图（去掉 title，兼容 GitHub）
    A["钓鱼网站 / 假网站"] -->|"无法伪造"| B["每个网站的钥匙都不同"]
    C["密码泄露"] -->|"无密码可偷"| D["钥匙存在设备安全区"]
    E["假网站攻击"] -->|"验证失败"| F["网站身份会被自动校验"]
    G["重放攻击"] -->|"旧钥匙无效"| H["每次登录都是新挑战"]
    I["数据库泄露"] -->|"拿不到私钥"| J["网站仅保存公钥印模"]

```

通过这些机制，「通行密钥」提供了一种比传统密码更加可靠的安全保障。

---

## 如何为我的统一身份认证设置「通行密钥」？

你可以在登录页面点击“个人中心”，认证成功后在“个人中心”→“安全设置”→“通行密钥”中按照提示设置。  
目前支持：

- Windows（需要 Windows Hello）
- Mac
- iOS
- 原生 Android
- 大多数 OPPO、华为设备

---

## 如何使用「通行密钥」登录？

在添加了「通行密钥」的设备登录统一身份认证时：

1. 选择“通行密钥”
2. 输入账号
3. 按照提示操作即可

---

如在认证过程中遇到问题，请联系网络信息中心用户服务部：  
📧 邮箱： [nic@ustc.edu.cn](mailto:nic@ustc.edu.cn)  
📞 电话： +86-551-63600800

---
