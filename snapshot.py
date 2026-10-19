"""Keep the brief bounded; originals remain available through herald fact."""
import json
ORDER = 25
def section(con, ctx):
    status = con.execute("SELECT data FROM facts WHERE source='canvas' AND kind='status' AND external_id='api'").fetchone()
    if not status:
        return None
    state = json.loads(status[0])
    if state.get("login_required"):
        return "## Canvas\nYour Canvas authorization needs reconnecting."
    lines = ["## Canvas", "Last successful sync: " + state.get("last_sync", "unknown")]
    for row in con.execute("SELECT id,title,ts,data FROM facts WHERE source='canvas' AND kind='announcement' AND substr(ts,1,10)>=? ORDER BY ts DESC LIMIT 8", (ctx.today.isoformat(),)):
        data = json.loads(row["data"])
        lines.append(f"- Announcement fact {row['id']}: {data.get('course_code')}: {row['title']} ({row['ts']})")
    for row in con.execute("SELECT id,title,data FROM facts WHERE source='canvas' AND kind='conversation' AND json_extract(data,'$.workflow_state')='unread' ORDER BY ts DESC LIMIT 5"):
        lines.append(f"- Unread Canvas inbox header, fact {row['id']}: {row['title']}")
    return "\n".join(lines)
