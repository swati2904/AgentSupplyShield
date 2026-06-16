from app.github_file_discovery import GitHubTreeItem, discover_relevant_github_files


def test_discovers_relevant_files_in_priority_order() -> None:
    result = discover_relevant_github_files(
        [
            GitHubTreeItem(path="docs/usage.md", type="blob", size=200),
            GitHubTreeItem(path="src/app.py", type="blob", size=100),
            GitHubTreeItem(path="package.json", type="blob", size=120),
            GitHubTreeItem(path="schema/openapi.yaml", type="blob", size=300),
            GitHubTreeItem(path="README.md", type="blob", size=80),
            GitHubTreeItem(path="node_modules/pkg/README.md", type="blob", size=50),
            GitHubTreeItem(path="docs", type="tree"),
        ]
    )

    assert [file.path for file in result.selected_files] == [
        "README.md",
        "schema/openapi.yaml",
        "package.json",
        "docs/usage.md",
    ]
    assert [file.artifact_type for file in result.selected_files] == [
        "readme",
        "tool_schema",
        "package_manifest",
        "documentation",
    ]
    assert any(skip.path == "src/app.py" and skip.reason == "unsupported_file" for skip in result.skipped_paths)
    assert any(skip.path == "node_modules/pkg/README.md" and skip.reason == "ignored_path" for skip in result.skipped_paths)
    assert any(skip.path == "docs" and skip.reason == "not_a_file" for skip in result.skipped_paths)


def test_accepts_dict_items_from_github_tree_api() -> None:
    result = discover_relevant_github_files(
        [
            {"path": "README.md", "type": "blob", "size": 42},
            {"path": ".well-known/ai-plugin.json", "type": "blob", "size": 90},
        ]
    )

    assert [file.path for file in result.selected_files] == [
        "README.md",
        ".well-known/ai-plugin.json",
    ]
    assert result.selected_files[1].selection_reason == "tool_schema"


def test_skips_large_secret_ignored_and_unsafe_paths() -> None:
    result = discover_relevant_github_files(
        [
            GitHubTreeItem(path="docs/large.md", type="blob", size=11),
            GitHubTreeItem(path=".env.example", type="blob", size=5),
            GitHubTreeItem(path="dist/README.md", type="blob", size=5),
            GitHubTreeItem(path="../README.md", type="blob", size=5),
            GitHubTreeItem(path="docs\\guide.md", type="blob", size=5),
        ],
        max_file_size_bytes=10,
    )

    assert result.selected_files == []
    assert any(skip.path == "docs/large.md" and skip.reason == "file_too_large" for skip in result.skipped_paths)
    assert any(skip.path == ".env.example" and skip.reason == "ignored_path" for skip in result.skipped_paths)
    assert any(skip.path == "dist/README.md" and skip.reason == "ignored_path" for skip in result.skipped_paths)
    assert any(skip.path == "../README.md" and skip.reason == "unsafe_path" for skip in result.skipped_paths)
    assert any(skip.path == "docs\\guide.md" and skip.reason == "unsafe_path" for skip in result.skipped_paths)


def test_limits_selected_files_deterministically() -> None:
    result = discover_relevant_github_files(
        [
            GitHubTreeItem(path="docs/zeta.md", type="blob", size=5),
            GitHubTreeItem(path="docs/alpha.md", type="blob", size=5),
            GitHubTreeItem(path="docs/beta.md", type="blob", size=5),
        ],
        max_selected_files=2,
    )

    assert [file.path for file in result.selected_files] == ["docs/alpha.md", "docs/beta.md"]
    assert any(skip.path == "docs/zeta.md" and skip.reason == "selection_limit" for skip in result.skipped_paths)


def test_selects_package_manifests_and_mcp_schema_names() -> None:
    result = discover_relevant_github_files(
        [
            GitHubTreeItem(path="server/mcp-server.yaml", type="blob", size=90),
            GitHubTreeItem(path="pyproject.toml", type="blob", size=140),
            GitHubTreeItem(path="requirements.txt", type="blob", size=70),
            GitHubTreeItem(path="package-lock.json", type="blob", size=70),
        ]
    )

    assert [file.path for file in result.selected_files] == [
        "server/mcp-server.yaml",
        "pyproject.toml",
        "requirements.txt",
    ]
    assert any(skip.path == "package-lock.json" and skip.reason == "ignored_path" for skip in result.skipped_paths)
