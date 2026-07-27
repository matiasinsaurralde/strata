from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from strata.git_repo import (
    GitRepository,
    InvalidRepositoryPathError,
    InvalidRevisionError,
    stable_repository_hash,
)


def git(repository: Path, *arguments: str) -> str:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test Author",
        "GIT_AUTHOR_EMAIL": "author@example.test",
        "GIT_COMMITTER_NAME": "Test Committer",
        "GIT_COMMITTER_EMAIL": "committer@example.test",
    }
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=10,
    )
    return result.stdout.strip()


def commit_all(repository: Path, message: str) -> str:
    git(repository, "add", "-A")
    git(repository, "commit", "-m", message)
    return git(repository, "rev-parse", "HEAD")


@pytest.fixture
def synthetic_repository(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    repository = tmp_path / "source"
    repository.mkdir()
    subprocess.run(
        ["git", "-C", str(repository), "init", "-b", "main"],
        check=True,
        capture_output=True,
        timeout=10,
    )

    (repository / "app.txt").write_text("root line\n", encoding="utf-8")
    root = commit_all(repository, "root commit")

    (repository / "app.txt").write_text("root line\nneedle security fix\n", encoding="utf-8")
    ordinary = commit_all(repository, "ordinary commit")

    git(repository, "mv", "app.txt", "renamed.txt")
    rename = commit_all(repository, "rename app")

    git(repository, "checkout", "-b", "feature")
    (repository / "feature.txt").write_text("feature branch\n", encoding="utf-8")
    feature = commit_all(repository, "feature")

    git(repository, "checkout", "main")
    (repository / "main.txt").write_text("main branch\n", encoding="utf-8")
    main = commit_all(repository, "main work")
    git(repository, "merge", "--no-ff", "feature", "-m", "merge feature")
    merge = git(repository, "rev-parse", "HEAD")
    return repository, {
        "root": root,
        "ordinary": ordinary,
        "rename": rename,
        "feature": feature,
        "main": main,
        "merge": merge,
    }


def test_mirror_metadata_root_merge_and_rename(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, shas = synthetic_repository
    repository = GitRepository(source, cache_root=tmp_path / "cache")
    snapshot = repository.fetch()

    assert snapshot.default_branch == "main"
    assert snapshot.head_sha == shas["merge"]
    assert snapshot.mirror_path.name == f"{stable_repository_hash(source)}.git"
    assert git(snapshot.mirror_path, "rev-parse", "--is-bare-repository") == "true"

    commits = repository.enumerate_commits(last=20)
    by_sha = {commit.sha: commit for commit in commits}
    assert by_sha[shas["root"]].is_root
    assert b"root line" in by_sha[shas["root"]].patch
    assert by_sha[shas["root"]].changed_paths[0].status == "A"

    merge = by_sha[shas["merge"]]
    assert merge.is_merge
    assert len(merge.parents) == 2
    assert b"feature.txt" in merge.patch
    assert {path.path for path in merge.changed_paths} == {"feature.txt"}

    rename = by_sha[shas["rename"]]
    rename_path = next(path for path in rename.changed_paths if path.status.startswith("R"))
    assert rename_path.old_path == "app.txt"
    assert rename_path.path == "renamed.txt"
    assert rename.patch_id is not None


def test_bounded_repository_read_tools(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, shas = synthetic_repository
    repository = GitRepository(source, cache_root=tmp_path / "cache")
    repository.fetch()

    assert repository.read_blob("HEAD", "renamed.txt").endswith(b"needle security fix\n")
    assert repository.read_range("HEAD", "renamed.txt", 2, 2) == ("needle security fix\n")
    matches = repository.search_text("HEAD", "needle")
    assert [(match.path, match.line) for match in matches] == [("renamed.txt", 2)]
    assert "renamed.txt" in repository.list_paths("HEAD")
    history = repository.path_history("HEAD", "renamed.txt", max_commits=5)
    assert history[0].sha == shas["rename"]
    blame = repository.blame("HEAD", "renamed.txt", start_line=2, end_line=2)
    assert blame[0].revision == shas["ordinary"]
    assert blame[0].text == "needle security fix"

    ranged = repository.enumerate_shas(revision_range=f"{shas['root']}..{shas['merge']}")
    assert shas["root"] not in ranged
    assert shas["merge"] in ranged
    assert repository.enumerate_shas(since="2000-01-01")


def test_fetch_detects_changed_head_and_reuses_mirror(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, _ = synthetic_repository
    repository = GitRepository(source, cache_root=tmp_path / "cache")
    first = repository.fetch()

    (source / "later.txt").write_text("later\n", encoding="utf-8")
    later = commit_all(source, "later")
    second = repository.fetch()

    assert second.mirror_path == first.mirror_path
    assert second.head_sha == later
    assert second.head_sha != first.head_sha


def test_untrusted_revision_and_path_validation(tmp_path: Path) -> None:
    remote = GitRepository(
        "https://example.test/owner/repository.git",
        cache_root=tmp_path / "cache",
    )
    assert remote.mirror_path.parent == (tmp_path / "cache").resolve()

    with pytest.raises(InvalidRevisionError):
        from strata.git_repo import validate_revision

        validate_revision("--upload-pack=evil")
    with pytest.raises(InvalidRevisionError):
        from strata.git_repo import validate_revision

        validate_revision("HEAD@{1}")
    with pytest.raises(InvalidRepositoryPathError):
        from strata.git_repo import validate_path

        validate_path("../secret")
