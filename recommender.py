from datetime import datetime


def compute_recommendation(projects):
    if not projects:
        return None

    scored = []
    for p in projects:
        if p.get("file_count", 0) < 2:
            continue

        score = 0
        reasons = []

        # Factor 1: closest to done (TODO completion)
        total = p.get("todos_total", 0)
        done = p.get("todos_done", 0)
        if total > 0:
            pct = done / total
            if pct >= 0.7:
                score += 40
                reasons.append(f"{done}/{total} TODOs done ({pct:.0%})")
            elif pct >= 0.4:
                score += 20
                reasons.append(f"{done}/{total} TODOs done ({pct:.0%})")

        # Factor 2: priority tags
        pri = p.get("priority")
        if pri == "P0":
            score += 50
            reasons.append("P0 priority")
        elif pri == "P1":
            score += 30
            reasons.append("P1 priority")
        elif pri == "P2":
            score += 15
            reasons.append("P2 priority")

        # Factor 3: recency -- favor projects with recent activity (momentum)
        age = p.get("last_activity_days")
        if age is not None:
            if age < 1:
                score += 25
                reasons.append("active today")
            elif age < 3:
                score += 15
                reasons.append(f"active {age:.0f}d ago")
            elif age > 7:
                score -= 5

        # Factor 4: has errors (urgent attention)
        if p.get("has_errors"):
            score += 20
            reasons.append("has errors in logs")

        # Factor 5: has CLAUDE.md (well-defined project)
        if p.get("has_claude_md"):
            score += 5

        # Factor 6: has SESSION_NOTES (context available)
        if p.get("has_session_notes_md"):
            score += 5

        # Penalize empty/minimal projects
        if p.get("file_count", 0) < 5:
            score -= 10

        scored.append((score, reasons, p))

    scored.sort(key=lambda x: x[0], reverse=True)

    if not scored:
        return {
            "recommendation": None,
            "reason": "No projects with enough context to recommend.",
        }

    top_score, top_reasons, top = scored[0]
    result = {
        "recommendation": top["name"],
        "reason": "; ".join(top_reasons) if top_reasons else "most substantial project",
        "score": top_score,
    }

    if len(scored) > 1:
        _, runner_reasons, runner = scored[1]
        result["runner_up"] = runner["name"]
        result["runner_up_reason"] = (
            "; ".join(runner_reasons) if runner_reasons else "next best candidate"
        )

    if len(scored) > 2:
        _, also_reasons, also = scored[2]
        result["also_consider"] = also["name"]
        result["also_consider_reason"] = (
            "; ".join(also_reasons) if also_reasons else "worth finishing"
        )

    return result
