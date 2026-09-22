"""
rule_engine.py
--------------
Applies predefined rule-based checks (Section 3.10.1, "Algorithm for
Rule-Based Detection"):

    BEGIN RuleBasedCheck(activity)
        alerts = []
        IF activity.timestamp.hour < 6 OR activity.timestamp.hour > 20 THEN
            alerts.append("After-hours access")
        IF activity.data_volume_mb > ORG_MAX_DOWNLOAD_MB THEN
            alerts.append("Excessive data download")
        IF activity.resource_accessed IN RESTRICTED_RESOURCES
           AND activity.user.role NOT authorized_for(resource) THEN
            alerts.append("Unauthorized resource access")
        RETURN alerts
    END

Thresholds (login window, ORG_MAX_DOWNLOAD_MB, and the restricted
resource -> authorized-role map) come from the single-row RuleConfig
table rather than being hard-coded, so an administrator can tune them via
the "Configure Detection Rules and Thresholds" screen without a code
change.
"""

import json

from models import ActivityLog, MonitoredUser, RuleConfig


def get_active_config() -> RuleConfig:
    """Return the single active RuleConfig row, creating a default one
    on first run if none exists yet."""
    from extensions import db

    config = RuleConfig.query.first()
    if config is None:
        config = RuleConfig()
        db.session.add(config)
        db.session.commit()
    return config


def _restricted_resources(config: RuleConfig) -> dict:
    """resource_name -> list of authorized roles."""
    try:
        return json.loads(config.restricted_resources_json or "{}")
    except (TypeError, ValueError):
        return {}


def authorized_for(role: str, resource: str, config: RuleConfig) -> bool:
    """True if `role` is allowed to access `resource` per RuleConfig."""
    restricted = _restricted_resources(config)
    if resource not in restricted:
        # Not a restricted resource at all -> no authorization check needed.
        return True
    return role in restricted[resource]


def rule_based_check(activity: ActivityLog, user: MonitoredUser, config: RuleConfig = None) -> list:
    """
    RuleBasedCheck(activity) -> list[str] of triggered rule descriptions.

    Mirrors the pseudocode in Section 3.10.1 exactly; the three checks
    are independent, so an activity can trigger zero, one, two, or all
    three flags.
    """
    if config is None:
        config = get_active_config()

    alerts = []

    # IF activity.timestamp.hour < 6 OR activity.timestamp.hour > 20
    hour = activity.timestamp.hour
    if hour < config.login_start_hour or hour > config.login_end_hour:
        alerts.append("After-hours access")

    # IF activity.data_volume_mb > ORG_MAX_DOWNLOAD_MB
    if activity.data_volume_mb is not None and activity.data_volume_mb > config.max_download_mb:
        alerts.append("Excessive data download")

    # IF activity.resource_accessed IN RESTRICTED_RESOURCES
    #    AND activity.user.role NOT authorized_for(resource)
    restricted = _restricted_resources(config)
    resource = activity.resource_accessed
    if resource and resource in restricted and not authorized_for(user.role, resource, config):
        alerts.append("Unauthorized resource access")

    return alerts
