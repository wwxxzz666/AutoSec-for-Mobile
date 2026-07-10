"""配置解析"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class BackendConfig(BaseModel):
    framework: str = "fastapi"  # django | flask | fastapi
    source_dir: str = "./backend"
    api_base_url: Optional[str] = None  # DAST 测试目标，为空则跳过 Stage 3


class MobileConfig(BaseModel):
    framework: str = "react-native"  # react-native | flutter | uniapp
    source_dir: str = "./mobile"
    platforms: list[str] = Field(default_factory=lambda: ["android", "ios"])
    mobsf_url: Optional[str] = None
    mobsf_api_key_env_var: str = "MOBSF_API_KEY"


class AuthConfig(BaseModel):
    type: str = "jwt"  # jwt | oauth | api-key | session
    token_env_var: str = "AUTH_TOKEN"  # 从环境变量读取 token


class PipelineConfig(BaseModel):
    skip_stages: list[str] = Field(default_factory=list)
    aboutsecurity_path: Optional[str] = None  # AboutSecurity 知识库路径


class ScanConfig(BaseModel):
    """完整扫描配置"""

    backend: BackendConfig = Field(default_factory=BackendConfig)
    mobile: MobileConfig = Field(default_factory=MobileConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanConfig:
        """从 YAML 文件加载配置"""
        p = Path(path)
        if not p.exists():
            return cls()
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)

    @classmethod
    def load(
        cls,
        project_root: str | Path | None = None,
        config_path: str | Path | None = None,
    ) -> ScanConfig:
        """Load configuration and resolve project-relative paths."""
        root = Path(project_root).resolve() if project_root else Path.cwd().resolve()
        config_file = Path(config_path) if config_path else root / ".mobilesec" / "config.yaml"
        if not config_file.is_absolute():
            config_file = root / config_file
        config = cls.from_yaml(config_file)
        # 环境变量覆盖
        env_url = os.environ.get("MOBILESEC_API_URL")
        if env_url:
            config.backend.api_base_url = env_url
        env_as_path = os.environ.get("ABOUTSECURITY_PATH")
        if env_as_path:
            config.pipeline.aboutsecurity_path = env_as_path
        env_mobsf_url = os.environ.get("MOBILESEC_MOBSF_URL")
        if env_mobsf_url:
            config.mobile.mobsf_url = env_mobsf_url

        for section in (config.backend, config.mobile):
            value = Path(section.source_dir).expanduser()
            if not value.is_absolute():
                value = root / value
            section.source_dir = str(value.resolve())

        if config.pipeline.aboutsecurity_path:
            kb_path = Path(config.pipeline.aboutsecurity_path).expanduser()
            if not kb_path.is_absolute():
                kb_path = root / kb_path
            config.pipeline.aboutsecurity_path = str(kb_path.resolve())
        return config
