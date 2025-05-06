import logging
from smart_community.models import AuditLog

logger = logging.getLogger('smart_community')

def log_action(user, action, details):
    logger.info(f"User: {user.username if user else 'Anonymous'}, Action: {action}, Details: {details}")
    AuditLog.objects.create(user=user, action=action, details=details)