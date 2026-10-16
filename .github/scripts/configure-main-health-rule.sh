#!/usr/bin/env bash
set -euo pipefail

repo="${GITHUB_REPOSITORY:-}"
apply=false
remove_user=false
baseline=""

usage() {
  cat <<'EOF'
Usage:
  .github/scripts/configure-main-health-rule.sh --baseline-sha <sha> [--apply] [--remove-user-bypass]

By default this prints a dry-run candidate and changes nothing. --apply updates
ruleset 25212714 only after verifying the current main head has a successful
main-health status. Removing the named-user bypass is a separate explicit
rollout approval: pass --remove-user-bypass only when authorized.
EOF
}

while (($#)); do
  case "$1" in
    --baseline-sha)
      (($# >= 2)) || { usage >&2; exit 2; }
      baseline="$2"
      shift 2
      ;;
    --apply)
      apply=true
      shift
      ;;
    --remove-user-bypass)
      remove_user=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$baseline" =~ ^[0-9a-f]{40}$ ]] || {
  echo "A full --baseline-sha is required." >&2
  exit 2
}
if [[ -z "$repo" ]]; then
  repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
fi
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "Invalid repository name." >&2
  exit 2
}

main_head="$(gh api "repos/$repo/commits/main" --jq .sha)"
[[ "$main_head" == "$baseline" ]] || {
  echo "Baseline must equal current main head ($main_head)." >&2
  exit 1
}
status="$(gh api "repos/$repo/commits/$baseline/status")"
[[ "$(jq -r '.state' <<<"$status")" == success ]] || {
  echo "The combined baseline commit status is not green." >&2
  exit 1
}
[[ "$(jq -r '[.statuses[] | select(.context == "main-health" and .state == "success")] | length' <<<"$status")" -gt 0 ]] || {
  echo "Baseline has no successful main-health status." >&2
  exit 1
}

ruleset="$(gh api "repos/$repo/rulesets/25212714")"
jq -e '
  .target == "branch"
  and .enforcement == "active"
  and (.conditions.ref_name.include == ["refs/heads/main"])
' >/dev/null <<<"$ruleset" || {
  echo "Ruleset 25212714 is not an active main-only branch ruleset; refusing to edit." >&2
  exit 1
}

actors="$(jq -c '[.bypass_actors[]? | {actor_id, actor_type}] | sort_by(.actor_type, .actor_id)' <<<"$ruleset")"
admin_count="$(jq '[.[] | select(.actor_type == "RepositoryRole" and .actor_id == 5)] | length' <<<"$actors")"
user_count="$(jq '[.[] | select(.actor_type == "User" and .actor_id == 5489990)] | length' <<<"$actors")"
unexpected="$(jq '[.[] | select((.actor_type != "RepositoryRole" or .actor_id != 5) and ( .actor_type != "User" or .actor_id != 5489990))] | length' <<<"$actors")"
[[ "$admin_count" -eq 1 && "$unexpected" -eq 0 ]] || {
  echo "Unexpected bypass configuration; expected repository admins role 5 and optionally user 5489990." >&2
  exit 1
}
if [[ "$user_count" -gt 0 && "$remove_user" != true && "$apply" == true ]]; then
  echo "Refusing to activate admins-only bypass while user 5489990 remains. Obtain approval, then pass --remove-user-bypass." >&2
  exit 1
fi
if [[ "$remove_user" == true && "$user_count" -eq 0 ]]; then
  echo "Named user bypass 5489990 is not present; no exception to remove." >&2
  exit 1
fi

if [[ "$remove_user" == true ]]; then
  remove_user_json=true
else
  remove_user_json=false
fi

candidate="$(
  jq --argjson remove_user "$remove_user_json" '
    . as $root
    | .rules = (
        [.rules[]? | if .type == "required_status_checks" then
          .parameters.required_status_checks =
            ((.parameters.required_status_checks // [])
             | map(select(.context != "main-health"))
             + [{"context":"main-health","integration_id":15368}])
          else . end]
        | if any(.[]; .type == "required_status_checks") then .
          else . + [{"type":"required_status_checks","parameters":{
            "required_status_checks":[{"context":"main-health","integration_id":15368}],
            "strict_required_status_checks_policy":true
          }}] end
      )
    | if $remove_user then
        .bypass_actors = [.bypass_actors[]? | select(.actor_type != "User" or .actor_id != 5489990)]
      else . end
    | {name,target,enforcement,conditions,rules,bypass_actors}
  ' <<<"$ruleset"
)"

echo "Dry-run candidate for ruleset 25212714 (existing rules preserved):"
jq . <<<"$candidate"
if [[ "$user_count" -gt 0 && "$remove_user" != true ]]; then
  echo "WARNING: this candidate retains user 5489990 bypass; remove it only with the separately approved --remove-user-bypass flag." >&2
fi
if [[ "$apply" != true ]]; then
  echo "No changes made. Add --apply to update after reviewed baseline and rollout approval."
  exit 0
fi

actor="$(gh api user --jq .login)"
permission="$(gh api "repos/$repo/collaborators/$actor/permission" --jq .permission)"
[[ "$permission" == admin ]] || {
  echo "Only a verified repository administrator may apply this ruleset update." >&2
  exit 1
}
gh api --method PUT "repos/$repo/rulesets/25212714" --input - <<<"$candidate" >/dev/null
echo "Updated ruleset 25212714: main-health is required with Actions integration 15368."
if [[ "$user_count" -gt 0 && "$remove_user" == true ]]; then
  echo "Removed named user bypass 5489990 with explicit --remove-user-bypass approval."
fi
