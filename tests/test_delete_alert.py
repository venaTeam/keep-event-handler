from sqlmodel import select

from src.core.db.db import delete_alert
from src.core.dependencies import SINGLE_TENANT_UUID
from src.models.db.alert import AlertAudit, CommentMention


def test_delete_alert_cascades_comment_mentions(db_session):
    """Regression: delete_alert must remove CommentMention rows for the alert's
    audits without raising. The app-side cascade deletes CommentMention via a
    subquery WHERE, which the default synchronize_session='evaluate' cannot
    evaluate ("Cannot evaluate SelectOfScalar")."""
    fingerprint = "fp-delete-cascade"

    audit = AlertAudit(
        fingerprint=fingerprint,
        tenant_id=SINGLE_TENANT_UUID,
        user_id="tester",
        action="commented",
        description="mentions someone",
    )
    db_session.add(audit)
    db_session.commit()
    audit_id = audit.id

    db_session.add(
        CommentMention(
            comment_id=audit_id,
            mentioned_user_id="someone",
            tenant_id=SINGLE_TENANT_UUID,
        )
    )
    db_session.commit()

    delete_alert(fingerprint=fingerprint, session=db_session)

    assert (
        db_session.exec(
            select(AlertAudit).where(AlertAudit.fingerprint == fingerprint)
        ).first()
        is None
    )
    assert (
        db_session.exec(
            select(CommentMention).where(CommentMention.comment_id == audit_id)
        ).first()
        is None
    )
