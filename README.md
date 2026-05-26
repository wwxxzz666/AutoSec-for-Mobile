# AutoSec for Mobile

移动应用安全扫描 Agent，集成 GitHub Actions CI/CD，基于 [AboutSecurity](https://github.com/wgpsec/AboutSecurity) 知识库驱动，帮助团队在开发流程中持续保障移动应用安全。

## 它能做什么

AutoSec for Mobile 是一个自动化安全扫描工具，专为移动应用（React Native / Flutter / UniApp）+ Python 后端（Django / Flask / FastAPI）设计。它会自动扫描你的代码和依赖中的安全问题，生成可读的报告，并在发现严重漏洞时发出告警。

**你不需要是安全专家**，只需要放一个配置文件，其余全自动。

### 扫描能力

| 阶段 | 扫描内容 | 需要的工具 |
|------|---------|-----------|
| 依赖审计 | 检查第三方依赖中的已知 CVE | Trivy（推荐）、pip-audit、npm audit |
| 静态代码分析 | 硬编码密钥、SQL 注入、不安全配置 | Semgrep（推荐）、Bandit |
| API 安全测试 | 注入测试、认证绕过、CORS 检查 | Nuclei、SQLMap |
| 移动端安全 | 硬编码凭据、不安全存储、Manifest/plist 配置 | 无需额外工具 |
| 报告生成 | 汇总所有结果，按严重级别排序 | 无 |

> 所有外部工具都是**可选的**。没安装只是跳过对应检测，不会报错。

### 扫描报告示例

```markdown
# 安全扫描报告

- **后端框架**: fastapi
- **移动端框架**: react-native

## 执行摘要
**结论**: 发现 2 个高危漏洞，需要立即修复。

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 0 |
| HIGH     | 2 |
| MEDIUM   | 0 |
| LOW      | 1 |

### [HIGH] 硬编码敏感信息: 硬编码密钥
**文件**: `backend/main.py` (第 4 行)
**修复建议**: 将敏感信息移至环境变量或密钥管理服务
```

## 快速开始

### 1. 安装

```bash
pip install -e .
```

### 2. 创建配置文件

在项目根目录创建 `.mobilesec/config.yaml`：

```yaml
backend:
  framework: fastapi           # django | flask | fastapi
  source_dir: ./backend        # Python 后端代码目录
  api_base_url: ""             # API 测试地址，留空跳过 API 安全测试

mobile:
  framework: react-native      # react-native | flutter | uniapp
  source_dir: ./mobile         # 移动端代码目录
  platforms:
    - android
    - ios

auth:
  type: jwt                    # jwt | oauth | api-key | session
  token_env_var: AUTH_TOKEN    # 认证 Token 的环境变量名
```

### 3. 运行扫描

```bash
# 基础扫描（依赖审计 + 静态分析 + 移动端）
mobilesec

# 指定 AboutSecurity 知识库路径
mobilesec --aboutsecurity-path /path/to/AboutSecurity

# 只运行特定阶段
mobilesec --stages dependency,sast

# 详细日志
mobilesec -v
```

### 4. GitHub Actions 集成

将以下文件放入你的仓库：

`.github/workflows/security-scan.yml`：

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 2 * * *"  # 每天凌晨执行

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      issues: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: 安装 AutoSec
        run: pip install -e .

      - name: 执行安全扫描
        run: mobilesec --stages dependency,sast,mobile
```

> 严重/高危漏洞会自动创建 GitHub Issue 并阻塞 PR 合并。

## 项目结构

```
src/mobilesec/
├── cli.py              # CLI 入口
├── config.py           # 配置解析
├── knowledge.py        # AboutSecurity 知识消费层
├── models.py           # 数据模型
├── stages/
│   ├── dependency.py   # 依赖审计
│   ├── sast.py         # 静态代码分析
│   ├── dast.py         # API 安全测试
│   ├── mobile.py       # 移动端安全检查
│   └── report.py       # 报告生成
└── tools/
    ├── base.py         # 工具执行基类
    ├── semgrep.py      # Semgrep 多语言 SAST
    ├── bandit.py       # Bandit Python 安全检查
    ├── trivy.py        # Trivy 依赖扫描
    ├── nuclei.py       # Nuclei 漏洞扫描
    ├── sqlmap.py       # SQLMap 注入测试
    └── mobsf.py        # MobSF 移动端分析
```

## 技术栈

- **语言**: Python 3.10+
- **数据模型**: Pydantic v2
- **知识库**: AboutSecurity（246 Skills + 649 Vuln）
- **CI/CD**: GitHub Actions

## 关于 AboutSecurity 知识库

[AboutSecurity](https://github.com/wgpsec/AboutSecurity) 是一个结构化渗透测试知识库，包含 200+ 安全技能方法论、600+ 漏洞数据、字典库和攻击载荷。AutoSec for Mobile 通过解析其 Skills/Vuln/Payload/Dic 四类数据，为扫描提供知识驱动。

配置 `--aboutsecurity-path` 后，Agent 会自动匹配与你项目相关的漏洞条目和安全方法论。

## License

MIT
