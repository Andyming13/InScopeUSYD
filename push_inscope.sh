#!/usr/bin/env bash
set -euo pipefail

# === Config / Inputs ===
COMMIT_MSG="${1:-Update branding: InScopeI1 -> InScope}"
REMOTE_URL_INPUT="${2:-}"

# === Helpers ===
echo_step () { printf "\n\033[1;34m▶ %s\033[0m\n" "$1"; }
echo_ok   () { printf "\033[1;32m✓ %s\033[0m\n" "$1"; }
echo_warn () { printf "\033[1;33m! %s\033[0m\n" "$1"; }

# === 0) Sanity: must run inside project folder ===
echo_step "Project directory: $(pwd)"
if [ ! -f "index.html" ] && [ ! -f "README.md" ]; then
  echo_warn "Didn't find index.html or README.md in current folder. Make sure you're in your repo root."
fi

# === 1) Init git repo if needed ===
if git rev-parse --git-dir > /dev/null 2>&1; then
  echo_ok "Git repo detected."
else
  echo_step "Initializing a new Git repository…"
  git init
  echo_ok "Initialized."
fi

# === 2) Ensure branch: main ===
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'main')"
if [ "$CURRENT_BRANCH" != "main" ]; then
  echo_step "Switching to 'main' branch…"
  # Create or rename to main
  if git show-ref --verify --quiet refs/heads/main; then
    git checkout main
  else
    # If current is 'master' or others, rename; else create if detached
    if [ "$CURRENT_BRANCH" != "HEAD" ]; then
      git branch -M main
    else
      git checkout -b main
    fi
  fi
  echo_ok "On branch 'main'."
else
  echo_ok "Already on 'main'."
fi

# === 3) Remote setup ===
REMOTE_NAME="origin"
REMOTE_URL_EXISTING="$(git remote get-url $REMOTE_NAME 2>/dev/null || true)"

if [ -n "$REMOTE_URL_INPUT" ]; then
  if [ -n "$REMOTE_URL_EXISTING" ]; then
    echo_step "Updating remote '$REMOTE_NAME' to: $REMOTE_URL_INPUT"
    git remote set-url "$REMOTE_NAME" "$REMOTE_URL_INPUT"
  else
    echo_step "Adding remote '$REMOTE_NAME': $REMOTE_URL_INPUT"
    git remote add "$REMOTE_NAME" "$REMOTE_URL_INPUT"
  fi
  REMOTE_URL="$REMOTE_URL_INPUT"
else
  if [ -n "$REMOTE_URL_EXISTING" ]; then
    REMOTE_URL="$REMOTE_URL_EXISTING"
    echo_ok "Using existing remote '$REMOTE_NAME': $REMOTE_URL"
  else
    echo_warn "No remote URL provided and none found. If this is a new repo, rerun with your GitHub URL, e.g.:"
    echo_warn "./push_inscope.sh \"$COMMIT_MSG\" \"https://github.com/<user>/<repo>.git\""
    exit 1
  fi
fi

# === 4) Pull (rebase) to avoid conflicts ===
echo_step "Fetching and rebasing from remote…"
# If upstream not set, set it temporarily on pull
if git rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
  git pull --rebase
else
  git pull --rebase "$REMOTE_NAME" main || true
fi
echo_ok "Pull (rebase) done."

# === 5) Stage & commit ===
echo_step "Staging changes…"
git add -A
if git diff --cached --quiet; then
  echo_warn "No changes to commit. If you haven't saved your edited HTML (InScopeI1 -> InScope), do that and rerun."
else
  echo_step "Committing…"
  git commit -m "$COMMIT_MSG"
  echo_ok "Committed."
fi

# === 6) Push ===
echo_step "Pushing to $REMOTE_NAME/main…"
# Ensure upstream
git push -u "$REMOTE_NAME" main
echo_ok "Push complete."

# === 7) Show Pages URL guess ===
REPO_PATH="${REMOTE_URL%.git}"
USER_ORG="$(echo "$REPO_PATH" | awk -F'github.com[:/]' '{print $2}' | awk -F'/' '{print $1}')"
REPO_NAME="$(echo "$REPO_PATH" | awk -F'/' '{print $NF}')"

PAGES_URL="https://${USER_ORG}.github.io/${REPO_NAME}/"
echo_step "Likely GitHub Pages URL:"
printf "   \033[1;36m%s\033[0m\n" "$PAGES_URL"
echo_ok "Done. Refresh in a few minutes to see the updated 'InScope' branding."