"""AboutSecurity 知识消费层"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class SkillMeta:
    """SKILL.md 的元数据"""

    name: str
    description: str
    tags: str = ""
    category: str = ""
    path: Path = field(default_factory=Path)

    @property
    def tag_list(self) -> list[str]:
        return [t.strip().lower() for t in self.tags.split(",") if t.strip()]

    def matches(self, keywords: list[str]) -> bool:
        """检查关键词是否匹配此 Skill"""
        text = f"{self.name} {self.description} {self.tags}".lower()
        return any(kw.lower() in text for kw in keywords)


@dataclass
class PayloadMeta:
    """Payload 目录的 _meta.yaml"""

    category: str
    description: str
    tags: str = ""
    files: list[dict] = field(default_factory=list)
    dir_path: Path = field(default_factory=Path)


@dataclass
class VulnEntry:
    """Vuln/ 中的漏洞条目"""

    id: str
    title: str
    product: str
    severity: str = ""
    tags: list[str] = field(default_factory=list)
    fingerprint: list[str] = field(default_factory=list)
    path: Path = field(default_factory=Path)


class KnowledgeBase:
    """AboutSecurity 知识库消费接口"""

    def __init__(self, base_path: str | Path):
        self.base_path = Path(base_path)
        self._skills: list[SkillMeta] = []
        self._payloads: list[PayloadMeta] = []
        self._vulns: list[VulnEntry] = []
        self._loaded = False

    @property
    def exists(self) -> bool:
        return self.base_path.exists()

    def load(self) -> None:
        """加载所有知识索引"""
        if self._loaded:
            return
        if not self.exists:
            logger.warning("AboutSecurity 路径不存在: %s", self.base_path)
            return

        self._load_skills()
        self._load_payloads()
        self._load_vulns()
        self._loaded = True
        logger.info(
            "知识库加载完成: %d Skills, %d Payload 目录, %d Vuln 条目",
            len(self._skills),
            len(self._payloads),
            len(self._vulns),
        )

    # ── Skills ──────────────────────────────────────────

    def _load_skills(self) -> None:
        skills_dir = self.base_path / "skills"
        if not skills_dir.exists():
            return
        for skill_md in skills_dir.rglob("SKILL.md"):
            meta = self._parse_skill_frontmatter(skill_md)
            if meta:
                self._skills.append(meta)

    def _parse_skill_frontmatter(self, path: Path) -> SkillMeta | None:
        try:
            content = path.read_text(encoding="utf-8")
            if not content.startswith("---"):
                return None
            end = content.find("---", 3)
            if end == -1:
                return None
            frontmatter = yaml.safe_load(content[3:end])
            if not frontmatter:
                return None
            metadata = frontmatter.get("metadata", {})
            return SkillMeta(
                name=frontmatter.get("name", path.parent.name),
                description=frontmatter.get("description", ""),
                tags=metadata.get("tags", ""),
                category=metadata.get("category", ""),
                path=path,
            )
        except Exception as e:
            logger.debug("解析 SKILL.md 失败 %s: %s", path, e)
            return None

    def search_skills(self, keywords: list[str]) -> list[SkillMeta]:
        """按关键词搜索 Skill"""
        self.load()
        return [s for s in self._skills if s.matches(keywords)]

    def get_skill(self, name: str) -> SkillMeta | None:
        """按名称获取 Skill"""
        self.load()
        for s in self._skills:
            if s.name == name:
                return s
        return None

    def read_skill_content(self, name: str) -> str | None:
        """读取 Skill 的完整内容"""
        skill = self.get_skill(name)
        if skill and skill.path.exists():
            return skill.path.read_text(encoding="utf-8")
        return None

    # ── Payload ─────────────────────────────────────────

    def _load_payloads(self) -> None:
        payload_dir = self.base_path / "Payload"
        if not payload_dir.exists():
            return
        for meta_file in payload_dir.rglob("_meta.yaml"):
            meta = self._parse_meta_yaml(meta_file)
            if meta:
                self._payloads.append(
                    PayloadMeta(
                        category=meta.get("category", ""),
                        description=meta.get("description", ""),
                        tags=meta.get("tags", ""),
                        files=meta.get("files", []),
                        dir_path=meta_file.parent,
                    )
                )

    def get_payload_files(self, category: str) -> list[Path]:
        """获取指定类型的 Payload 文件"""
        self.load()
        files = []
        for p in self._payloads:
            if p.category == category:
                for f in p.files:
                    fp = p.dir_path / f["name"]
                    if fp.exists():
                        files.append(fp)
        return files

    def load_payload_content(self, category: str, filename: str) -> str | None:
        """加载指定 Payload 文件内容"""
        self.load()
        for p in self._payloads:
            if p.category == category:
                fp = p.dir_path / filename
                if fp.exists():
                    return fp.read_text(encoding="utf-8")
        return None

    # ── Vuln ────────────────────────────────────────────

    def _load_vulns(self) -> None:
        vuln_dir = self.base_path / "Vuln"
        if not vuln_dir.exists():
            return
        for vuln_file in vuln_dir.rglob("*.md"):
            entry = self._parse_vuln_frontmatter(vuln_file)
            if entry:
                self._vulns.append(entry)

    def _parse_vuln_frontmatter(self, path: Path) -> VulnEntry | None:
        try:
            content = path.read_text(encoding="utf-8")
            if not content.startswith("---"):
                return None
            end = content.find("---", 3)
            if end == -1:
                return None
            fm = yaml.safe_load(content[3:end])
            if not fm:
                return None
            return VulnEntry(
                id=fm.get("id", path.stem),
                title=fm.get("title", ""),
                product=fm.get("product", ""),
                severity=fm.get("severity", ""),
                tags=fm.get("tags", []),
                fingerprint=fm.get("fingerprint", []),
                path=path,
            )
        except Exception as e:
            logger.debug("解析 Vuln 失败 %s: %s", path, e)
            return None

    def search_vulns(self, product: str | None = None, fingerprint: str | None = None) -> list[VulnEntry]:
        """搜索漏洞条目"""
        self.load()
        results = []
        for v in self._vulns:
            if product and v.product.lower() != product.lower():
                continue
            if fingerprint and fingerprint.lower() not in [f.lower() for f in v.fingerprint]:
                continue
            results.append(v)
        return results

    def read_vuln_content(self, vuln_id: str) -> str | None:
        """读取漏洞条目的完整内容"""
        self.load()
        for v in self._vulns:
            if v.id == vuln_id:
                return v.path.read_text(encoding="utf-8")
        return None

    # ── Dic ─────────────────────────────────────────────

    def get_dic_files(self, category: str, subcategory: str | None = None) -> list[Path]:
        """获取字典文件"""
        dic_dir = self.base_path / "Dic" / category
        if subcategory:
            dic_dir = dic_dir / subcategory
        if not dic_dir.exists():
            return []
        return [p for p in dic_dir.iterdir() if p.is_file() and p.name != "_meta.yaml"]

    def load_dic_content(self, category: str, filename: str) -> str | None:
        """加载字典文件内容"""
        fp = self.base_path / "Dic" / category / filename
        if fp.exists():
            return fp.read_text(encoding="utf-8")
        return None

    # ── 通用 ────────────────────────────────────────────

    def _parse_meta_yaml(self, path: Path) -> dict | None:
        try:
            with open(path, encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.debug("解析 _meta.yaml 失败 %s: %s", path, e)
            return None
