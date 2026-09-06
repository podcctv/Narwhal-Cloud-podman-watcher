#!/usr/bin/env bash
set -euo pipefail

REPO_URL_DEFAULT="https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git"
INSTALL_BASE_DEFAULT="/opt"

REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"
INSTALL_BASE_DIR="${INSTALL_BASE_DIR:-$INSTALL_BASE_DEFAULT}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] 请使用 root 运行：sudo bash bootstrap-install.sh"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] 未检测到 git，且当前系统不支持 apt-get 自动安装。请先手动安装 git。"
    exit 1
  fi
  echo "[INFO] 安装依赖: git"
  apt-get update
  apt-get install -y git
fi

mkdir -p "$INSTALL_BASE_DIR"

repo_name="$(basename "$REPO_URL")"
repo_name="${repo_name%.git}"
repo_dir="$INSTALL_BASE_DIR/$repo_name"

if [[ -d "$repo_dir/.git" ]]; then
  echo "[INFO] 检测到已存在仓库，执行更新: $repo_dir"
  branch="$(git -C "$repo_dir" symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
  if [[ -z "$branch" ]]; then
    branch="$(git -C "$repo_dir" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
    branch="${branch#origin/}"
  fi
  branch="${branch:-main}"

  git -C "$repo_dir" fetch --prune origin "$branch"
  remote_ref="origin/$branch"
  if ! git -C "$repo_dir" rev-parse --verify --quiet "$remote_ref^{commit}" >/dev/null; then
    echo "[ERROR] 无法解析远端分支: $remote_ref"
    exit 1
  fi

  backup_stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  if [[ -n "$(git -C "$repo_dir" status --porcelain --untracked-files=all)" ]]; then
    # The deployment repository must contain the exact release tree.  Preserve
    # operator edits (including untracked files) in Git before replacing it so
    # a newly tracked file cannot make an otherwise routine upgrade fail.
    echo "[WARN] 检测到本地修改；先保存到 Git stash，再切换到远端最新版。"
    git -C "$repo_dir" stash push --include-untracked \
      -m "narwhal-bootstrap before update $backup_stamp"
    echo "[INFO] 本地修改已保存到 $(git -C "$repo_dir" stash list -1 --format='%gd')。"
    echo "[INFO] 如需恢复，请先检查后执行: git -C '$repo_dir' stash pop"
  fi

  current_commit="$(git -C "$repo_dir" rev-parse HEAD)"
  remote_commit="$(git -C "$repo_dir" rev-parse "$remote_ref")"
  if ! git -C "$repo_dir" merge-base --is-ancestor "$current_commit" "$remote_commit"; then
    backup_branch="narwhal-bootstrap-backup-$backup_stamp"
    git -C "$repo_dir" branch "$backup_branch" "$current_commit"
    echo "[WARN] 本地提交与远端分叉，已保留到分支: $backup_branch"
  fi

  # Do not use git clean: ignored deployment configuration (for example .env)
  # and any files outside the repository stay untouched.
  git -C "$repo_dir" reset --hard "$remote_ref"
else
  echo "[INFO] 克隆仓库到: $repo_dir"
  git clone "$REPO_URL" "$repo_dir"
fi

echo "[INFO] 启动一键安装脚本..."
bash "$repo_dir/scripts/install.sh"
