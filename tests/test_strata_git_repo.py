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


def test_stream_commits_matches_per_commit_extraction(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    """The batched stream is byte-for-byte the per-``get_commit`` walk.

    Same order, same patch bytes (which feed triage and patch-id de-dup), same
    changed paths, same metadata -- across a root commit, a rename, a merge
    (first-parent diff), and a binary blob.
    """
    source, shas = synthetic_repository
    # A binary file exercises the GIT-binary-patch path through the stream.
    (source / "logo.bin").write_bytes(bytes(range(256)) * 4)
    binary = commit_all(source, "add binary asset")

    repository = GitRepository(source, cache_root=tmp_path / "cache")
    repository.fetch()

    baseline = repository.enumerate_commits(last=50)
    streamed = list(repository.stream_commits(last=50, compute_patch_id=True))

    assert [c.sha for c in streamed] == [c.sha for c in baseline]
    by_sha = {c.sha: c for c in streamed}
    assert binary in by_sha
    for base in baseline:
        got = by_sha[base.sha]
        assert got.patch == base.patch, f"patch bytes differ for {base.sha[:12]}"
        assert got.patch_id == base.patch_id
        assert got.message == base.message
        assert got.parents == base.parents
        assert got.committer_time == base.committer_time
        assert {(p.status[0], p.path) for p in got.changed_paths} == {
            (p.status[0], p.path) for p in base.changed_paths
        }

    merge = by_sha[shas["merge"]]
    assert merge.is_merge
    assert b"feature.txt" in merge.patch  # first-parent diff, as get_commit produces

    rename = by_sha[shas["rename"]]
    renamed = next(p for p in rename.changed_paths if p.status.startswith("R"))
    assert renamed.old_path == "app.txt"
    assert renamed.path == "renamed.txt"


def test_stream_commits_honours_last_and_revision(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, shas = synthetic_repository
    repository = GitRepository(source, cache_root=tmp_path / "cache")
    repository.fetch()

    # ``last`` caps newest-first, exactly like enumerate_shas.
    capped = list(repository.stream_commits(last=2))
    assert [c.sha for c in capped] == repository.enumerate_shas(last=2)

    # ``revision`` starts the walk elsewhere and excludes later history.
    from_rename = {c.sha for c in repository.stream_commits(revision=shas["rename"])}
    assert shas["rename"] in from_rename
    assert shas["merge"] not in from_rename
    assert shas["feature"] not in from_rename


def test_stream_commits_defaults_skip_patch_id(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    """Patch-id is opt-in: the prefilter never needs it, so the default pass
    does not spend a ``git patch-id`` process per commit."""
    source, _ = synthetic_repository
    repository = GitRepository(source, cache_root=tmp_path / "cache")
    repository.fetch()
    assert all(c.patch_id is None for c in repository.stream_commits(last=50))


def test_stream_commits_recovers_paths_with_spaces_and_unicode(
    tmp_path: Path,
) -> None:
    """Changed paths are derived from the patch, so paths Git does not quote in
    the ``diff --git`` header (spaces) and ones it does (non-ASCII) must both
    still match the authoritative ``--name-status`` extraction."""
    source = tmp_path / "spaced"
    source.mkdir()
    subprocess.run(
        ["git", "-C", str(source), "init", "-b", "main"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    (source / "my dir").mkdir()
    (source / "my dir" / "my file.py").write_text("x\n", encoding="utf-8")
    (source / "αβγ.py").write_text("y\n", encoding="utf-8")
    commit_all(source, "spaced and unicode paths")
    git(source, "mv", "my dir/my file.py", "my dir/renamed file.py")
    commit_all(source, "rename a spaced path")

    repository = GitRepository(source, cache_root=tmp_path / "cache")
    repository.fetch()
    baseline = {c.sha: c for c in repository.enumerate_commits(last=10)}
    for streamed in repository.stream_commits(last=10):
        base = baseline[streamed.sha]
        assert {(p.status[0], p.path) for p in streamed.changed_paths} == {
            (p.status[0], p.path) for p in base.changed_paths
        }


def test_stream_commits_caps_oversize_commit_and_keeps_walking(
    tmp_path: Path,
) -> None:
    """One commit whose patch exceeds the budget must not abort the walk.

    It is yielded with a truncated patch (enough to trip the caller's size gate,
    like get_commit failing for that commit alone) while the commits on either
    side of it come through intact -- the failure mode that a naive
    raise-out-of-the-generator would turn into a dead stream.
    """
    source = tmp_path / "big"
    source.mkdir()
    subprocess.run(
        ["git", "-C", str(source), "init", "-b", "main"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    (source / "before.py").write_text("before = 1\n", encoding="utf-8")
    commit_all(source, "before")
    # A patch comfortably past a deliberately small cap forces the overflow path.
    (source / "huge.py").write_text("row = 1\n" * 60_000, encoding="utf-8")
    huge = commit_all(source, "huge one")
    (source / "after.py").write_text("after = 1\n", encoding="utf-8")
    commit_all(source, "after")

    capped_repo = GitRepository(
        source, cache_root=tmp_path / "cache", max_patch_bytes=64 * 1024
    )
    capped_repo.fetch()
    streamed = list(capped_repo.stream_commits(last=10))

    by_subject = {c.message.splitlines()[0]: c for c in streamed}
    assert set(by_subject) == {"before", "huge one", "after"}

    # Neighbours are byte-intact against per-commit extraction taken with a cap
    # large enough not to trip on the huge commit (whose own get_commit would
    # raise -- precisely the dead-end the stream must route around).
    full_repo = GitRepository(
        source, cache_root=tmp_path / "full", max_patch_bytes=8 * 1024 * 1024
    )
    full_repo.fetch()
    baseline = {c.message.splitlines()[0]: c for c in full_repo.enumerate_commits(last=10)}
    for subject in ("before", "after"):
        assert by_subject[subject].patch == baseline[subject].patch

    # The oversize commit survived as a truncated prefix (shorter than its true
    # patch), still attributed to the right SHA, with no patch-id claimed.
    capped = by_subject["huge one"]
    assert capped.sha == huge
    assert 0 < len(capped.patch) < len(baseline["huge one"].patch)
    assert capped.patch_id is None


def test_stream_parsing_is_invariant_across_chunk_boundaries(
    tmp_path: Path,
) -> None:
    """The record parser must produce the same commits no matter how the git
    output is split into read chunks -- including a sentinel straddling a
    boundary and an oversize record arriving whole vs. piecemeal. This is where
    incremental stream parsers break, so it is checked at 1-byte granularity and
    around the cap and sentinel lengths."""
    source = tmp_path / "chunks"
    source.mkdir()
    subprocess.run(
        ["git", "-C", str(source), "init", "-b", "main"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    (source / "a.py").write_text("a\n", encoding="utf-8")
    commit_all(source, "first")
    (source / "big.py").write_text("r = 1\n" * 50_000, encoding="utf-8")  # ~300 KB
    commit_all(source, "big")
    (source / "b.py").write_text("b\n", encoding="utf-8")
    commit_all(source, "third")

    repository = GitRepository(source, cache_root=tmp_path / "cache", max_patch_bytes=64 * 1024)
    repository.fetch()
    import strata.git_repo as gr

    raw = b"".join(
        gr._stream_bounded(
            [
                *repository._base_git(),
                "log",
                "--topo-order",
                "--date-order",
                "--no-show-signature",
                "--patch",
                "--diff-merges=first-parent",
                "--find-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                "--full-index",
                f"--format={repository._STREAM_FORMAT}",
                repository.resolve_revision("main"),
                "--",
            ],
            timeout=30,
        )
    )

    def parse(size: int) -> list[tuple[str, int, str]]:
        def gen():
            for i in range(0, len(raw), size):
                yield raw[i : i + size]

        return [
            (c.sha, len(c.patch), c.message.splitlines()[0])
            for c in repository._parse_commit_stream(gen(), compute_patch_id=False)
        ]

    reference = parse(len(raw) + 1)  # one chunk
    assert [subject for _, _, subject in reference] == ["third", "big", "first"]
    for size in (1, 2, 3, 7, 13, 64, 1000, 65_535, 65_536, 65_537, 131_072):
        assert parse(size) == reference, f"chunk size {size} diverged"


def test_stream_commits_empty_commit_yields_empty_patch(
    synthetic_repository: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, _ = synthetic_repository
    git(source, "commit", "--allow-empty", "-m", "empty commit")
    empty_sha = git(source, "rev-parse", "HEAD")
    repository = GitRepository(source, cache_root=tmp_path / "cache")
    repository.fetch()

    streamed = {c.sha: c for c in repository.stream_commits(last=50)}
    baseline = {c.sha: c for c in repository.enumerate_commits(last=50)}
    assert streamed[empty_sha].patch == baseline[empty_sha].patch == b""
    assert streamed[empty_sha].changed_paths == ()


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
