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


def _repository_state(repository: Path) -> dict[str, str]:
    """Everything an in-place scan must leave untouched in the user's repo."""
    return {
        "refs": git(repository, "for-each-ref", "--format=%(refname) %(objectname)"),
        "head": git(repository, "rev-parse", "HEAD"),
        "status": git(repository, "status", "--porcelain"),
        "worktrees": git(repository, "worktree", "list", "--porcelain"),
    }


def test_in_place_grounds_existing_repo_without_cloning_or_mutating(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, shas = synthetic_repository
    cache = tmp_path / "cache"
    before = _repository_state(source)

    repository = GitRepository(source, cache_root=cache, in_place=True)
    assert repository.in_place is True
    assert repository.mirror_path.resolve() == (source / ".git").resolve()

    snapshot = repository.fetch()
    assert snapshot.default_branch == "main"
    assert snapshot.head_sha == shas["merge"]
    assert snapshot.mirror_path == repository.mirror_path

    # Nothing was copied into the cache: the scan reads the checkout directly.
    assert not cache.exists()

    # The bounded read tools operate against the live git directory.
    commits = {commit.sha: commit for commit in repository.enumerate_commits(last=20)}
    assert commits[shas["root"]].is_root
    assert commits[shas["merge"]].is_merge
    assert repository.read_blob("HEAD", "renamed.txt").endswith(b"needle security fix\n")
    assert [(m.path, m.line) for m in repository.search_text("HEAD", "needle")] == [
        ("renamed.txt", 2)
    ]

    # The user's repository is byte-for-byte as it was: same refs and head, a
    # clean tree, and no lingering worktree registrations.
    assert _repository_state(source) == before


def test_in_place_resolves_git_dir_from_a_subdirectory(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, shas = synthetic_repository
    nested = source / "nested" / "deep"
    nested.mkdir(parents=True)
    repository = GitRepository(nested, cache_root=tmp_path / "cache", in_place=True)
    assert repository.mirror_path.resolve() == (source / ".git").resolve()
    assert repository.fetch().head_sha == shas["merge"]


def test_in_place_rejects_a_non_git_directory(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(InvalidRepositoryPathError):
        GitRepository(plain, cache_root=tmp_path / "cache", in_place=True)


def test_in_place_flag_is_ignored_for_remote_sources(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    repository = GitRepository(
        "https://example.test/owner/repository.git",
        cache_root=cache,
        in_place=True,
    )
    assert repository.in_place is False
    assert repository.mirror_path == cache.resolve() / f"{repository.repository_hash}.git"


def test_in_place_reflects_new_commits_without_recloning(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, shas = synthetic_repository
    cache = tmp_path / "cache"
    repository = GitRepository(source, cache_root=cache, in_place=True)
    first = repository.fetch()
    assert first.head_sha == shas["merge"]

    (source / "late.txt").write_text("late\n", encoding="utf-8")
    late = commit_all(source, "late commit")
    second = repository.fetch()

    assert second.head_sha == late
    assert second.head_sha != first.head_sha
    assert not cache.exists()
