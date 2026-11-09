"""移动端检查规则回归测试。

历史问题：多个规则用 `"true" in content` 做判断，只要文件里任意位置出现
true（例如 android:exported="true"）就报 HIGH/MEDIUM，误报率高到没法用。
"""

from pathlib import Path

import pytest

from mobilesec.stages import mobile


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ---------------- _attr_is_true ----------------


@pytest.mark.parametrize(
    "content,attr,expected",
    [
        ('android:cleartextTrafficPermitted="true"', "cleartextTrafficPermitted", True),
        ("android:cleartextTrafficPermitted='true'", "cleartextTrafficPermitted", True),
        ("cleartextTrafficPermitted = \"true\"", "cleartextTrafficPermitted", True),
        ("javaScriptEnabled: true", "javaScriptEnabled", True),
        ('cleartextTrafficPermitted="false"', "cleartextTrafficPermitted", False),
        # 关键：别的属性是 true，目标属性是 false
        ('<a exported="true"/><b cleartextTrafficPermitted="false"/>', "cleartextTrafficPermitted", False),
        # 目标属性根本没有
        ('<a exported="true"/>', "cleartextTrafficPermitted", False),
        # 只有 true 关键字，没有目标属性
        ("const x = true", "allowFileAccess", False),
    ],
)
def test_attr_is_true(content, attr, expected):
    assert mobile._attr_is_true(content, attr) is expected


def test_plist_key_is_true():
    assert mobile._plist_key_is_true("<key>NSAllowsArbitraryLoads</key><true/>", "NSAllowsArbitraryLoads")
    assert mobile._plist_key_is_true("<key>NSAllowsArbitraryLoads</key> <true />", "NSAllowsArbitraryLoads")
    assert not mobile._plist_key_is_true("<key>NSAllowsArbitraryLoads</key><false/>", "NSAllowsArbitraryLoads")
    assert not mobile._plist_key_is_true("<key>Other</key><true/>", "NSAllowsArbitraryLoads")


# ---------------- _check_react_native ----------------


def _titles(findings):
    return [f.title for f in findings]


def test_cleartext_not_reported_when_false(tmp_path):
    """cleartextTrafficPermitted=false 但同文件别处有 true，不能报 HIGH。"""
    _write(
        tmp_path / "android/app/src/main/res/xml/network_security_config.xml",
        '<network-security-config><domain-config cleartextTrafficPermitted="false" exported="true"/></network-security-config>',
    )

    findings = mobile._check_react_native(tmp_path)

    assert "允许明文 HTTP 流量" not in _titles(findings)


def test_cleartext_reported_when_true(tmp_path):
    _write(
        tmp_path / "android/app/src/main/res/xml/network_security_config.xml",
        '<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>',
    )

    findings = mobile._check_react_native(tmp_path)

    assert "允许明文 HTTP 流量" in _titles(findings)


def test_allow_file_access_not_reported_when_false(tmp_path):
    _write(
        tmp_path / "src/WebView.js",
        "const props = { allowFileAccess: false, someFlag: true };",
    )

    findings = mobile._check_react_native(tmp_path)

    assert "WebView 允许文件访问" not in _titles(findings)


def test_allow_file_access_reported_when_true(tmp_path):
    _write(tmp_path / "src/WebView.js", "const props = { allowFileAccess: true };")

    findings = mobile._check_react_native(tmp_path)

    assert "WebView 允许文件访问" in _titles(findings)


def test_js_enabled_without_channel_reported(tmp_path):
    _write(tmp_path / "src/WebView.js", "const props = { javaScriptEnabled: true };")

    findings = mobile._check_react_native(tmp_path)

    assert "WebView 启用 JavaScript 但未设置安全通信" in _titles(findings)


def test_js_enabled_with_channel_not_reported(tmp_path):
    _write(
        tmp_path / "src/WebView.js",
        "const props = { javaScriptEnabled: true, onMessage: handler };",
    )

    findings = mobile._check_react_native(tmp_path)

    assert "WebView 启用 JavaScript 但未设置安全通信" not in _titles(findings)


# ---------------- _check_ios_plist ----------------


def test_ats_not_reported_when_value_false(tmp_path):
    """NSAllowsArbitraryLoads=false 不应报 HIGH（以前只判断键是否存在）。"""
    _write(
        tmp_path / "ios/App/Info.plist",
        """<plist><dict>
        <key>NSAppTransportSecurity</key>
        <dict>
            <key>NSAllowsArbitraryLoads</key>
            <false/>
        </dict>
        </dict></plist>""",
    )

    findings = mobile._check_ios_plist(tmp_path)

    assert "iOS App Transport Security 允许不安全连接" not in _titles(findings)


def test_ats_reported_when_value_true(tmp_path):
    _write(
        tmp_path / "ios/App/Info.plist",
        """<plist><dict>
        <key>NSAppTransportSecurity</key>
        <dict>
            <key>NSAllowsArbitraryLoads</key>
            <true/>
        </dict>
        </dict></plist>""",
    )

    findings = mobile._check_ios_plist(tmp_path)

    assert "iOS App Transport Security 允许不安全连接" in _titles(findings)
